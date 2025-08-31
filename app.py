from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import json
import uuid
import requests
import tempfile
import zipfile
from datetime import datetime
import subprocess
import re
import threading
import time
from supabase import create_client, Client
import google.generativeai as genai
try:
    import clang.cindex
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False
from pygments import highlight
from pygments.lexers import CLexer, CppLexer, NasmLexer
from pygments.formatters import JSONFormatter
from io import StringIO
import sys

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
SUPABASE_URL = os.environ.get('SUPABASE_URL', 'your-supabase-url')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', 'your-supabase-key')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', 'your-gemini-api-key')

# Initialize clients
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
genai.configure(api_key=GEMINI_API_KEY)
# Use the actual Gemini Code model (code-bison or code-gecko)
model = genai.GenerativeModel('code-bison')  # The actual coder model

# Multi-user session management
active_sessions = {}
file_locks = {}

# Initialize Clang for C/C++ parsing if available
if CLANG_AVAILABLE:
    try:
        clang.cindex.conf.set_library_path('/usr/lib/x86_64-linux-gnu/')
    except:
        pass

class CodeRoom:
    def __init__(self):
        # Advanced syntax patterns with real error detection
        self.c_includes = [
            '#include <stdio.h>', '#include <stdlib.h>', '#include <string.h>',
            '#include <unistd.h>', '#include <sys/types.h>', '#include <fcntl.h>'
        ]
        
    def check_c_syntax(self, code):
        """Advanced C syntax checking using clang if available"""
        errors = []
        warnings = []
        
        if CLANG_AVAILABLE:
            try:
                # Create temporary file for clang analysis
                with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as tmp:
                    tmp.write(code)
                    tmp_path = tmp.name
                
                # Use clang to parse and check syntax
                index = clang.cindex.Index.create()
                translation_unit = index.parse(tmp_path, args=['-std=c11', '-Wall', '-Wextra'])
                
                for diagnostic in translation_unit.diagnostics:
                    error_info = {
                        'line': diagnostic.location.line,
                        'column': diagnostic.location.column,
                        'message': diagnostic.spelling,
                        'severity': diagnostic.severity.name.lower(),
                        'category': diagnostic.category_name
                    }
                    
                    if diagnostic.severity >= clang.cindex.Diagnostic.Error:
                        errors.append(error_info)
                    else:
                        warnings.append(error_info)
                
                os.unlink(tmp_path)
                
            except Exception as e:
                # Fallback to basic pattern matching
                errors.extend(self.basic_c_check(code))
        else:
            # Use basic checking if clang is not available
            errors.extend(self.basic_c_check(code))
        
        return {'errors': errors, 'warnings': warnings}

    def check_cpp_syntax(self, code):
        """Advanced C++ syntax checking using clang++ if available"""
        errors = []
        warnings = []
        
        if CLANG_AVAILABLE:
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp', delete=False) as tmp:
                    tmp.write(code)
                    tmp_path = tmp.name
                
                index = clang.cindex.Index.create()
                translation_unit = index.parse(tmp_path, args=['-std=c++17', '-Wall', '-Wextra'])
                
                for diagnostic in translation_unit.diagnostics:
                    error_info = {
                        'line': diagnostic.location.line,
                        'column': diagnostic.location.column,
                        'message': diagnostic.spelling,
                        'severity': diagnostic.severity.name.lower(),
                        'category': diagnostic.category_name
                    }
                    
                    if diagnostic.severity >= clang.cindex.Diagnostic.Error:
                        errors.append(error_info)
                    else:
                        warnings.append(error_info)
                
                os.unlink(tmp_path)
                
            except Exception as e:
                errors.extend(self.basic_cpp_check(code))
        else:
            errors.extend(self.basic_cpp_check(code))
        
        return {'errors': errors, 'warnings': warnings}

    def check_assembly_syntax(self, code):
        """Assembly syntax checking using NASM if available"""
        errors = []
        warnings = []
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.asm', delete=False) as tmp:
                tmp.write(code)
                tmp_path = tmp.name
            
            # Try to assemble with NASM
            result = subprocess.run(
                ['nasm', '-f', 'elf64', tmp_path, '-o', '/dev/null'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                error_lines = result.stderr.split('\n')
                for line in error_lines:
                    if ':' in line and ('error' in line.lower() or 'warning' in line.lower()):
                        parts = line.split(':')
                        if len(parts) >= 3:
                            try:
                                line_num = int(parts[1])
                                message = ':'.join(parts[2:]).strip()
                                
                                error_info = {
                                    'line': line_num,
                                    'column': 1,
                                    'message': message,
                                    'severity': 'error' if 'error' in line.lower() else 'warning'
                                }
                                
                                if 'error' in line.lower():
                                    errors.append(error_info)
                                else:
                                    warnings.append(error_info)
                            except ValueError:
                                continue
            
            os.unlink(tmp_path)
            
        except subprocess.TimeoutExpired:
            errors.append({
                'line': 1,
                'column': 1,
                'message': 'Assembly check timed out',
                'severity': 'error'
            })
        except FileNotFoundError:
            # NASM not available, use basic checking
            errors.extend(self.basic_assembly_check(code))
        except Exception as e:
            errors.extend(self.basic_assembly_check(code))
        
        return {'errors': errors, 'warnings': warnings}

    def basic_c_check(self, code):
        """Fallback C syntax checking"""
        errors = []
        lines = code.split('\n')
        
        brace_count = 0
        paren_count = 0
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            
            # Check braces
            brace_count += line.count('{') - line.count('}')
            paren_count += line.count('(') - line.count(')')
            
            # Check common errors
            if line.endswith('{') or line.endswith('}'):
                continue
            elif not line.endswith(';') and not line.endswith('{') and not line.endswith('}') and not line.startswith('#'):
                if any(keyword in line for keyword in ['if', 'for', 'while', 'else']):
                    continue
                errors.append({
                    'line': i,
                    'column': len(line),
                    'message': 'Missing semicolon',
                    'severity': 'error'
                })
            
            # Check includes
            if line.startswith('#include') and '<' in line and '>' not in line:
                errors.append({
                    'line': i,
                    'column': len(line),
                    'message': 'Unclosed include directive',
                    'severity': 'error'
                })
        
        if brace_count != 0:
            errors.append({
                'line': len(lines),
                'column': 1,
                'message': f'Unmatched braces ({"missing" if brace_count > 0 else "extra"} {abs(brace_count)})',
                'severity': 'error'
            })
        
        return errors

    def basic_cpp_check(self, code):
        """Fallback C++ syntax checking"""
        errors = self.basic_c_check(code)
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # Check class syntax
            if line.startswith('class ') and not line.endswith('{') and not line.endswith(';'):
                errors.append({
                    'line': i,
                    'column': len(line),
                    'message': 'Incomplete class declaration',
                    'severity': 'error'
                })
            
            # Check namespace syntax
            if line.startswith('namespace ') and not line.endswith('{'):
                errors.append({
                    'line': i,
                    'column': len(line),
                    'message': 'Incomplete namespace declaration',
                    'severity': 'error'
                })
        
        return errors

    def basic_assembly_check(self, code):
        """Fallback Assembly syntax checking"""
        errors = []
        lines = code.split('\n')
        
        valid_registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 
                          'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']
        valid_instructions = ['mov', 'push', 'pop', 'call', 'ret', 'jmp', 'je', 'jne', 
                            'jg', 'jl', 'cmp', 'add', 'sub', 'mul', 'div', 'int', 'nop']
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            
            # Check labels
            if line.endswith(':'):
                label = line[:-1].strip()
                if not label or not label.replace('_', '').isalnum():
                    errors.append({
                        'line': i,
                        'column': 1,
                        'message': 'Invalid label name',
                        'severity': 'error'
                    })
                continue
            
            # Check instructions
            parts = line.split()
            if parts:
                instruction = parts[0].lower()
                if instruction not in valid_instructions:
                    errors.append({
                        'line': i,
                        'column': 1,
                        'message': f'Unknown instruction: {instruction}',
                        'severity': 'warning'
                    })
        
        return errors

    def check_syntax(self, code, language):
        """Main syntax checking function with real libraries"""
        if language.lower() == 'c':
            return self.check_c_syntax(code)
        elif language.lower() == 'cpp':
            return self.check_cpp_syntax(code)
        elif language.lower() == 'assembly':
            return self.check_assembly_syntax(code)
        else:
            return {'errors': [], 'warnings': []}

    def get_ai_suggestions(self, code, language, prompt="", error_context=""):
        """Enhanced AI suggestions using Gemini Code model"""
        try:
            # Construct detailed prompt for code model
            system_context = f"""You are an expert {language.upper()} developer specializing in operating system development. 
            You have deep knowledge of:
            - Low-level system programming and kernel development
            - Memory management and hardware interfaces  
            - Assembly optimization and C/C++ best practices for OS development
            - Security vulnerabilities and performance optimization
            
            Provide specific, actionable suggestions for OS development."""
            
            full_prompt = f"""
            {system_context}
            
            Language: {language.upper()}
            Code to analyze:
            ```{language}
            {code}
            ```
            
            User request: {prompt}
            
            {f"Current errors/warnings: {error_context}" if error_context else ""}
            
            Please provide:
            1. **Code Quality Analysis**: Identify potential bugs, memory leaks, and security issues
            2. **OS-Specific Improvements**: Suggest optimizations for kernel/system code
            3. **Performance Optimization**: Recommend faster algorithms or better memory usage
            4. **Security Considerations**: Point out potential vulnerabilities
            5. **Best Practices**: Suggest modern {language} practices for OS development
            
            Format your response with clear sections and specific line references where applicable.
            Prioritize critical issues that could cause system crashes or security vulnerabilities.
            """
            
            response = model.generate_content(full_prompt)
            return response.text
            
        except Exception as e:
            return f"AI service error: {str(e)}. Please check your Gemini API key and try again."

    def get_code_completion(self, code, cursor_line, cursor_col, language):
        """Get intelligent code completion suggestions"""
        try:
            context_lines = code.split('\n')
            current_line = context_lines[cursor_line] if cursor_line < len(context_lines) else ""
            
            completion_prompt = f"""
            Provide code completion for {language.upper()} in an OS development context.
            
            Current code context:
            ```{language}
            {code}
            ```
            
            Current line (cursor position): {current_line}
            Line number: {cursor_line + 1}
            
            Suggest 3-5 most likely code completions for this context. 
            Focus on:
            - Function calls relevant to OS development
            - Variable names following kernel naming conventions
            - System calls and hardware interfaces
            - Memory management functions
            
            Return only the completion suggestions, one per line, without explanation.
            """
            
            response = model.generate_content(completion_prompt)
            completions = [line.strip() for line in response.text.split('\n') if line.strip()]
            
            return completions[:5]  # Return top 5 suggestions
            
        except Exception as e:
            return []

    def analyze_code_complexity(self, code, language):
        """Analyze code complexity and provide metrics"""
        lines = code.split('\n')
        metrics = {
            'lines_of_code': len([l for l in lines if l.strip() and not l.strip().startswith('//')]),
            'comment_lines': len([l for l in lines if l.strip().startswith('//')]),
            'cyclomatic_complexity': 1,  # Base complexity
            'function_count': 0,
            'potential_issues': []
        }
        
        # Count functions and complexity
        for line in lines:
            line = line.strip()
            
            # Function definitions
            if re.match(r'\w+\s+\w+\s*\([^)]*\)\s*{?', line) and not line.startswith('//'):
                metrics['function_count'] += 1
            
            # Complexity contributors
            complexity_keywords = ['if', 'else', 'while', 'for', 'switch', 'case', 'catch']
            for keyword in complexity_keywords:
                if f' {keyword} ' in f' {line} ' or line.startswith(f'{keyword} '):
                    metrics['cyclomatic_complexity'] += 1
            
            # Potential issues
            if 'malloc(' in line and 'free(' not in code:
                metrics['potential_issues'].append('Potential memory leak: malloc without corresponding free')
            
            if 'strcpy(' in line:
                metrics['potential_issues'].append('Security risk: strcpy can cause buffer overflow, consider strncpy')
            
            if 'gets(' in line:
                metrics['potential_issues'].append('Security vulnerability: gets() is unsafe, use fgets() instead')
        
                metrics = 2048
                return metrics
                    top_p=0.8
                )
            )
            
            return response.text
            
        except Exception as e:
            return f"AI service error: {str(e)}. Please check your Gemini API key and try again."

    def get_code_completion(self, code, cursor_line, cursor_col, language):
        """Get intelligent code completion suggestions"""
        try:
            context_lines = code.split('\n')
            current_line = context_lines[cursor_line] if cursor_line < len(context_lines) else ""
            
            completion_prompt = f"""
            Provide code completion for {language.upper()} in an OS development context.
            
            Current code context:
            ```{language}
            {code}
            ```
            
            Current line (cursor position): {current_line}
            Line number: {cursor_line + 1}
            
            Suggest 3-5 most likely code completions for this context. 
            Focus on:
            - Function calls relevant to OS development
            - Variable names following kernel naming conventions
            - System calls and hardware interfaces
            - Memory management functions
            
            Return only the completion suggestions, one per line, without explanation.
            """
            
            response = model.generate_content(completion_prompt)
            completions = [line.strip() for line in response.text.split('\n') if line.strip()]
            
            return completions[:5]  # Return top 5 suggestions
            
        except Exception as e:
            return []

    def analyze_code_complexity(self, code, language):
        """Analyze code complexity and provide metrics"""
        lines = code.split('\n')
        metrics = {
            'lines_of_code': len([l for l in lines if l.strip() and not l.strip().startswith('//')]),
            'comment_lines': len([l for l in lines if l.strip().startswith('//')]),
            'cyclomatic_complexity': 1,  # Base complexity
            'function_count': 0,
            'potential_issues': []
        }
        
        # Count functions and complexity
        for line in lines:
            line = line.strip()
            
            # Function definitions
            if re.match(r'\w+\s+\w+\s*\([^)]*\)\s*{?', line) and not line.startswith('//'):
                metrics['function_count'] += 1
            
            # Complexity contributors
            complexity_keywords = ['if', 'else', 'while', 'for', 'switch', 'case', 'catch']
            for keyword in complexity_keywords:
                if f' {keyword} ' in f' {line} ' or line.startswith(f'{keyword} '):
                    metrics['cyclomatic_complexity'] += 1
            
            # Potential issues
            if 'malloc(' in line and 'free(' not in code:
                metrics['potential_issues'].append('Potential memory leak: malloc without corresponding free')
            
            if 'strcpy(' in line:
                metrics['potential_issues'].append('Security risk: strcpy can cause buffer overflow, consider strncpy')
            
            if 'gets(' in line:
                metrics['potential_issues'].append('Security vulnerability: gets() is unsafe, use fgets() instead')
        
        return metrics

code_room = CodeRoom()

# File locking system for multi-user editing
def acquire_file_lock(file_id, user_id):
    if file_id in file_locks:
        if file_locks[file_id] != user_id:
            return False
    file_locks[file_id] = user_id
    return True

def release_file_lock(file_id, user_id):
    if file_id in file_locks and file_locks[file_id] == user_id:
        del file_locks[file_id]
        return True
    return False
@socketio.on('join_file')
def on_join_file(data):
    file_id = data['file_id']
    user_id = session.get('user_id')
    
    join_room(file_id)
    
    if file_id not in active_sessions:
        active_sessions[file_id] = set()
    
    active_sessions[file_id].add(user_id)
    
    emit('user_joined', {
        'user_id': user_id,
        'active_users': list(active_sessions[file_id])
    }, room=file_id)

@socketio.on('leave_file')
def on_leave_file(data):
    file_id = data['file_id']
    user_id = session.get('user_id')
    
    leave_room(file_id)
    
    if file_id in active_sessions:
        active_sessions[file_id].discard(user_id)
        if not active_sessions[file_id]:
            del active_sessions[file_id]
    
    emit('user_left', {
        'user_id': user_id,
        'active_users': list(active_sessions.get(file_id, []))
    }, room=file_id)

@socketio.on('code_change')
def on_code_change(data):
    file_id = data['file_id']
    user_id = session.get('user_id')
    
    # Broadcast code changes to other users
    emit('code_updated', {
        'content': data['content'],
        'user_id': user_id,
        'cursor_pos': data.get('cursor_pos')
    }, room=file_id, include_self=False)

@socketio.on('cursor_move')
def on_cursor_move(data):
    file_id = data['file_id']
    user_id = session.get('user_id')
    
    emit('cursor_updated', {
        'user_id': user_id,
        'cursor_pos': data['cursor_pos']
    }, room=file_id, include_self=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/repos', methods=['GET'])
def get_repos():
    try:
        response = supabase.table('repositories').select('*').execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repos', methods=['POST'])
def create_repo():
    try:
        data = request.json
        repo_data = {
            'id': str(uuid.uuid4()),
            'name': data['name'],
            'description': data.get('description', ''),
            'created_at': datetime.now().isoformat(),
            'owner': session.get('user_id', 'anonymous')
        }
        
        response = supabase.table('repositories').insert(repo_data).execute()
        
        # Create main branch
        branch_data = {
            'id': str(uuid.uuid4()),
            'repo_id': repo_data['id'],
            'name': 'main',
            'created_at': datetime.now().isoformat(),
            'created_by': session.get('user_id', 'anonymous')
        }
        supabase.table('branches').insert(branch_data).execute()
        
        return jsonify(response.data[0])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repos/<repo_id>/branches', methods=['GET'])
def get_branches(repo_id):
    try:
        response = supabase.table('branches').select('*').eq('repo_id', repo_id).execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repos/<repo_id>/branches', methods=['POST'])
def create_branch(repo_id):
    try:
        data = request.json
        branch_data = {
            'id': str(uuid.uuid4()),
            'repo_id': repo_id,
            'name': data['name'],
            'created_at': datetime.now().isoformat(),
            'created_by': session.get('user_id', 'anonymous')
        }
        
        response = supabase.table('branches').insert(branch_data).execute()
        return jsonify(response.data[0])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files', methods=['GET'])
def get_files():
    try:
        branch_id = request.args.get('branch_id')
        response = supabase.table('files').select('*').eq('branch_id', branch_id).execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files', methods=['POST'])
def save_file():
    try:
        data = request.json
        user_id = session.get('user_id')
        
        # Check file lock
        file_key = f"{data['branch_id']}_{data['filename']}"
        if not acquire_file_lock(file_key, user_id):
            return jsonify({'error': 'File is being edited by another user'}), 423
        
        # Check if file exists
        existing = supabase.table('files').select('*').eq('branch_id', data['branch_id']).eq('filename', data['filename']).execute()
        
        file_data = {
            'branch_id': data['branch_id'],
            'filename': data['filename'],
            'content': data['content'],
            'language': data.get('language', 'c'),
            'updated_at': datetime.now().isoformat(),
            'updated_by': user_id
        }
        
        if existing.data:
            # Update existing file
            response = supabase.table('files').update(file_data).eq('id', existing.data[0]['id']).execute()
        else:
            # Create new file
            file_data['id'] = str(uuid.uuid4())
            file_data['created_at'] = datetime.now().isoformat()
            response = supabase.table('files').insert(file_data).execute()
        
        # Release lock after successful save
        release_file_lock(file_key, user_id)
        
        return jsonify(response.data[0])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/lock', methods=['POST'])
def lock_file():
    try:
        data = request.json
        file_key = f"{data['branch_id']}_{data['filename']}"
        user_id = session.get('user_id')
        
        if acquire_file_lock(file_key, user_id):
            return jsonify({'locked': True, 'user_id': user_id})
        else:
            return jsonify({'locked': False, 'locked_by': file_locks.get(file_key)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/unlock', methods=['POST'])
def unlock_file():
    try:
        data = request.json
        file_key = f"{data['branch_id']}_{data['filename']}"
        user_id = session.get('user_id')
        
        released = release_file_lock(file_key, user_id)
        return jsonify({'released': released})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/active-users/<file_id>')
def get_active_users(file_id):
    try:
        users = list(active_sessions.get(file_id, []))
        return jsonify({'active_users': users})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/syntax-check', methods=['POST'])
def check_syntax():
    try:
        data = request.json
        code = data['code']
        language = data['language']
        
        result = code_room.check_syntax(code, language)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai-assist', methods=['POST'])
def ai_assist():
    try:
        data = request.json
        code = data['code']
        language = data['language']
        prompt = data.get('prompt', '')
        
        # Get current syntax errors for context
        syntax_result = code_room.check_syntax(code, language)
        error_context = ""
        if syntax_result.get('errors'):
            error_context = f"Current errors: {syntax_result['errors']}"
        
        suggestions = code_room.get_ai_suggestions(code, language, prompt, error_context)
        return jsonify({'suggestions': suggestions})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/code-completion', methods=['POST'])
def code_completion():
    try:
        data = request.json
        code = data['code']
        cursor_line = data.get('cursor_line', 0)
        cursor_col = data.get('cursor_col', 0)
        language = data['language']
        
        completions = code_room.get_code_completion(code, cursor_line, cursor_col, language)
        return jsonify({'completions': completions})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-complexity', methods=['POST'])
def analyze_complexity():
    try:
        data = request.json
        code = data['code']
        language = data['language']
        
        metrics = code_room.analyze_code_complexity(code, language)
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<branch_id>')
def download_branch(branch_id):
    try:
        # Get branch info
        branch_response = supabase.table('branches').select('*').eq('id', branch_id).execute()
        if not branch_response.data:
            return jsonify({'error': 'Branch not found'}), 404
        
        branch = branch_response.data[0]
        
        # Get all files in branch
        files_response = supabase.table('files').select('*').eq('branch_id', branch_id).execute()
        files = files_response.data
        
        # Create temporary zip file
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, f"{branch['name']}-{branch_id[:8]}.zip")
        
        with zipfile.ZipFile(zip_path, 'w') as zip_file:
            for file in files:
                zip_file.writestr(file['filename'], file['content'])
        
        return send_file(zip_path, as_attachment=True, download_name=f"{branch['name']}-{branch_id[:8]}.zip")
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload-repo', methods=['POST'])
def upload_repo():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        repo_name = request.form.get('repo_name', 'Uploaded Repository')
        
        # Extract zip file
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, file.filename)
        file.save(zip_path)
        
        # Create repository
        repo_data = {
            'id': str(uuid.uuid4()),
            'name': repo_name,
            'description': 'Uploaded repository',
            'created_at': datetime.now().isoformat(),
            'owner': session.get('user_id', 'anonymous')
        }
        
        repo_response = supabase.table('repositories').insert(repo_data).execute()
        
        # Create main branch
        branch_data = {
            'id': str(uuid.uuid4()),
            'repo_id': repo_data['id'],
            'name': 'main',
            'created_at': datetime.now().isoformat(),
            'created_by': session.get('user_id', 'anonymous')
        }
        
        branch_response = supabase.table('branches').insert(branch_data).execute()
        
        # Extract and save files
        with zipfile.ZipFile(zip_path, 'r') as zip_file:
            for filename in zip_file.namelist():
                if not filename.endswith('/'):  # Skip directories
                    content = zip_file.read(filename).decode('utf-8', errors='ignore')
                    language = 'c'
                    if filename.endswith(('.cpp', '.cxx', '.cc')):
                        language = 'cpp'
                    elif filename.endswith(('.asm', '.s')):
                        language = 'assembly'
                    
                    file_data = {
                        'id': str(uuid.uuid4()),
                        'branch_id': branch_data['id'],
                        'filename': filename,
                        'content': content,
                        'language': language,
                        'created_at': datetime.now().isoformat(),
                        'updated_at': datetime.now().isoformat(),
                        'updated_by': session.get('user_id', 'anonymous')
                    }
                    
                    supabase.table('files').insert(file_data).execute()
        
        return jsonify(repo_response.data[0])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# HTML Template
html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Code Room - AI Collaborative Coding</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/codemirror.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/theme/monokai.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/addon/hint/show-hint.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/codemirror.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/mode/clike/clike.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/mode/gas/gas.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/addon/hint/show-hint.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/addon/hint/clike-hint.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/addon/edit/closebrackets.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/addon/edit/matchbrackets.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/addon/lint/lint.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a1a;
            color: white;
            height: 100vh;
            overflow: hidden;
        }

        .header {
            background: #2d2d2d;
            border-bottom: 2px solid white;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }

        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #00ff88;
        }

        .controls {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .btn {
            background: #404040;
            color: white;
            border: 1px solid white;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
        }

        .btn:hover {
            background: #505050;
            transform: translateY(-1px);
        }

        .btn.primary {
            background: #00ff88;
            color: #1a1a1a;
        }

        .btn.primary:hover {
            background: #00cc6a;
        }

        .main-container {
            display: flex;
            height: calc(100vh - 80px);
        }

        .sidebar {
            width: 300px;
            background: #2d2d2d;
            border-right: 2px solid white;
            padding: 20px;
            overflow-y: auto;
        }

        .sidebar h3 {
            margin-bottom: 15px;
            color: #00ff88;
            border-bottom: 1px solid white;
            padding-bottom: 5px;
        }

        .repo-item, .branch-item, .file-item {
            background: #404040;
            border: 1px solid white;
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .repo-item:hover, .branch-item:hover, .file-item:hover {
            background: #505050;
            transform: translateX(5px);
        }

        .repo-item.active, .branch-item.active, .file-item.active {
            background: #00ff88;
            color: #1a1a1a;
        }

        .editor-container {
            flex: 1;
            display: flex;
            flex-direction: column;
        }

        .editor-header {
            background: #2d2d2d;
            border-bottom: 1px solid white;
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }

        .editor-tabs {
            display: flex;
            gap: 5px;
        }

        .tab {
            background: #404040;
            color: white;
            border: 1px solid white;
            padding: 8px 16px;
            border-radius: 4px 4px 0 0;
            cursor: pointer;
        }

        .tab.active {
            background: #00ff88;
            color: #1a1a1a;
        }

        .editor-wrapper {
            flex: 1;
            position: relative;
        }

        .CodeMirror {
            height: 100% !important;
            font-size: 14px;
        }

        .ai-panel {
            width: 400px;
            background: #2d2d2d;
            border-left: 2px solid white;
            display: flex;
            flex-direction: column;
        }

        .ai-tabs {
            display: flex;
            background: #404040;
            border-bottom: 1px solid white;
        }

        .ai-tab {
            flex: 1;
            padding: 10px;
            text-align: center;
            cursor: pointer;
            border-right: 1px solid white;
            transition: all 0.3s;
        }

        .ai-tab:last-child {
            border-right: none;
        }

        .ai-tab.active {
            background: #00ff88;
            color: #1a1a1a;
        }

        .ai-tab:hover:not(.active) {
            background: #505050;
        }

        .ai-content {
            flex: 1;
            overflow-y: auto;
        }

        .ai-section {
            padding: 15px;
            display: none;
        }

        .ai-section.active {
            display: block;
        }

        .complexity-metrics {
            background: #1f2f4d;
            border: 1px solid #6bb6ff;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
        }

        .metric-item {
            display: flex;
            justify-content: space-between;
            margin: 8px 0;
            padding: 5px 0;
            border-bottom: 1px solid #444;
        }

        .metric-item:last-child {
            border-bottom: none;
        }

        .severity-error {
            color: #ff6b6b;
            font-weight: bold;
        }

        .severity-warning {
            color: #ffa500;
        }

        .severity-info {
            color: #6bb6ff;
        }

        .error-details {
            background: #4d1f1f;
            border-left: 4px solid #ff6b6b;
            padding: 10px;
            margin: 5px 0;
            border-radius: 0 4px 4px 0;
        }

        .warning-details {
            background: #4d3d1f;
            border-left: 4px solid #ffa500;
            padding: 10px;
            margin: 5px 0;
            border-radius: 0 4px 4px 0;
        }

        .code-completion {
            background: #2f1f4d;
            border: 1px solid #9966ff;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
        }

        .completion-item {
            padding: 8px;
            cursor: pointer;
            border-radius: 4px;
            margin: 2px 0;
            font-family: monospace;
            transition: all 0.3s;
        }

        .completion-item:hover {
            background: #404040;
        }

        .real-time-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #00ff88;
            border-radius: 50%;
            margin-left: 5px;
            animation: pulse 2s infinite;
        }

        .user-indicator {
            position: absolute;
            top: 5px;
            right: 5px;
            background: #00ff88;
            color: #1a1a1a;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: bold;
        }

        .collaboration-panel {
            background: #404040;
            border-bottom: 1px solid white;
            padding: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .active-users {
            display: flex;
            gap: 10px;
        }

        .user-avatar {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            background: #00ff88;
            color: #1a1a1a;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 12px;
        }

        .file-lock-indicator {
            background: #ff6b6b;
            color: white;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 12px;
            margin-left: 10px;
        }

        .cursor-marker {
            position: absolute;
            border-left: 2px solid;
            height: 18px;
            z-index: 100;
            animation: blink 1s infinite;
        }

        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }

        .input-group {
            margin: 10px 0;
        }

        .input-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }

        .input-group input, .input-group select, .input-group textarea {
            width: 100%;
            background: #404040;
            color: white;
            border: 1px solid white;
            padding: 8px;
            border-radius: 4px;
        }

        .error-list {
            background: #4d1f1f;
            border: 1px solid #ff6b6b;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
        }

        .error-item {
            margin: 5px 0;
            font-size: 12px;
        }

        .suggestions {
            background: #1f4d1f;
            border: 1px solid #6bff6b;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
            white-space: pre-wrap;
            font-size: 12px;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
        }

        .modal-content {
            background: #2d2d2d;
            margin: 10% auto;
            padding: 20px;
            border: 2px solid white;
            border-radius: 8px;
            width: 90%;
            max-width: 500px;
        }

        .close {
            color: white;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }

        .close:hover {
            color: #00ff88;
        }

        @media (max-width: 768px) {
            .main-container {
                flex-direction: column;
            }
            
            .sidebar {
                width: 100%;
                height: 200px;
            }
            
            .ai-panel {
                width: 100%;
                height: 250px;
            }
            
            .controls {
                justify-content: center;
            }
            
            .header {
                flex-direction: column;
                gap: 10px;
            }
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #404040;
            border-radius: 50%;
            border-top-color: #00ff88;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .status-bar {
            background: #404040;
            border-top: 1px solid white;
            padding: 5px 20px;
            font-size: 12px;
            display: flex;
            justify-content: space-between;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🏠 The Code Room</div>
        <div class="controls">
            <button class="btn" onclick="openModal('createRepoModal')">New Repo</button>
            <button class="btn" onclick="openModal('createBranchModal')">New Branch</button>
            <button class="btn" onclick="openModal('uploadModal')">Upload Repo</button>
            <button class="btn primary" onclick="saveCurrentFile()">Save File</button>
            <button class="btn" onclick="downloadBranch()">Download Branch</button>
        </div>
    </div>

    <div class="main-container">
        <div class="sidebar">
            <h3>Repositories</h3>
            <div id="repos-list"></div>
            
            <h3>Branches</h3>
            <div id="branches-list"></div>
            
            <h3>Files</h3>
            <div id="files-list"></div>
        </div>

        <div class="editor-container">
            <div class="collaboration-panel">
                <div class="active-users" id="active-users">
                    <span>👥 Active Users:</span>
                </div>
                <div id="file-lock-status"></div>
            </div>
            
            <div class="editor-header">
                <div class="editor-tabs">
                    <div class="tab active" id="current-tab">main.c</div>
                </div>
                <div class="file-info">
                    <span id="current-language">C</span> | 
                    <span id="current-branch">main</span>
                    <span id="real-time-status" class="real-time-indicator"></span>
                </div>
            </div>
            
            <div class="editor-wrapper">
                <textarea id="code-editor">#include <stdio.h>

int main() {
    printf("Welcome to The Code Room!\\n");
    return 0;
}</textarea>
            </div>
            
            <div class="status-bar">
                <div id="status-left">Ready</div>
                <div id="status-right">Line 1, Col 1</div>
            </div>
        </div>

        <div class="ai-panel">
            <div class="ai-tabs">
                <div class="ai-tab active" onclick="switchAITab('assistant')">🤖 Assistant</div>
                <div class="ai-tab" onclick="switchAITab('syntax')">🔍 Syntax</div>
                <div class="ai-tab" onclick="switchAITab('metrics')">📊 Metrics</div>
                <div class="ai-tab" onclick="switchAITab('completion')">💡 Complete</div>
            </div>
            
            <div class="ai-content">
                <!-- AI Assistant Tab -->
                <div id="assistant-section" class="ai-section active">
                    <div class="input-group">
                        <label>Ask AI for help: <span class="real-time-indicator"></span></label>
                        <textarea id="ai-prompt" placeholder="e.g., 'Optimize this kernel function', 'Fix memory management', 'Add interrupt handling'"></textarea>
                        <button class="btn primary" onclick="getAIHelp()" style="margin-top: 10px;">Get AI Suggestions</button>
                    </div>
                    <div id="ai-suggestions"></div>
                </div>
                
                <!-- Syntax Check Tab -->
                <div id="syntax-section" class="ai-section">
                    <div class="input-group">
                        <button class="btn" onclick="checkSyntax()">🔍 Advanced Syntax Check</button>
                        <button class="btn" onclick="autoFixErrors()" style="margin-top: 5px;">🔧 Auto-Fix Errors</button>
                    </div>
                    <div id="syntax-errors"></div>
                </div>
                
                <!-- Code Metrics Tab -->
                <div id="metrics-section" class="ai-section">
                    <div class="input-group">
                        <button class="btn" onclick="analyzeComplexity()">📊 Analyze Code</button>
                    </div>
                    <div id="complexity-metrics"></div>
                </div>
                
                <!-- Code Completion Tab -->
                <div id="completion-section" class="ai-section">
                    <div class="input-group">
                        <label>Smart Completions:</label>
                        <button class="btn" onclick="getCompletions()">💡 Get Suggestions</button>
                    </div>
                    <div id="code-completions"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Modals -->
    <div id="createRepoModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('createRepoModal')">&times;</span>
            <h2>Create New Repository</h2>
            <div class="input-group">
                <label>Repository Name:</label>
                <input type="text" id="repo-name" placeholder="My OS Project">
            </div>
            <div class="input-group">
                <label>Description:</label>
                <textarea id="repo-description" placeholder="Operating system project"></textarea>
            </div>
            <button class="btn primary" onclick="createRepo()">Create Repository</button>
        </div>
    </div>

    <div id="createBranchModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('createBranchModal')">&times;</span>
            <h2>Create New Branch</h2>
            <div class="input-group">
                <label>Branch Name:</label>
                <input type="text" id="branch-name" placeholder="feature-memory-management">
            </div>
            <button class="btn primary" onclick="createBranch()">Create Branch</button>
        </div>
    </div>

    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('uploadModal')">&times;</span>
            <h2>Upload Repository</h2>
            <div class="input-group">
                <label>Repository Name:</label>
                <input type="text" id="upload-repo-name" placeholder="Uploaded Project">
            </div>
            <div class="input-group">
                <label>ZIP File:</label>
                <input type="file" id="repo-file" accept=".zip">
            </div>
            <button class="btn primary" onclick="uploadRepo()">Upload Repository</button>
        </div>
    </div>

    <script>
        let currentRepo = null;
        let currentBranch = null;
        let currentFile = null;
        let editor = null;
        let socket = null;
        let userId = null;
        let isFileOwner = false;
        let otherCursors = {};

        // Initialize everything
        document.addEventListener('DOMContentLoaded', function() {
            // Generate or get user ID
            userId = sessionStorage.getItem('userId') || generateUserId();
            sessionStorage.setItem('userId', userId);
            
            // Initialize Socket.IO
            socket = io();
            setupSocketListeners();
            
            // Initialize CodeMirror with advanced features
            editor = CodeMirror.fromTextArea(document.getElementById('code-editor'), {
                mode: 'text/x-csrc',
                theme: 'monokai',
                lineNumbers: true,
                autoCloseBrackets: true,
                matchBrackets: true,
                indentUnit: 4,
                indentWithTabs: false,
                lineWrapping: true,
                extraKeys: {
                    "Ctrl-Space": "autocomplete",
                    "Ctrl-/": "toggleComment",
                    "Ctrl-D": "selectNextOccurrence"
                },
                hintOptions: {
                    completeSingle: false,
                    hint: customHint
                },
                gutters: ["CodeMirror-lint-markers", "CodeMirror-linenumbers"],
                lint: true
            });

            // Real-time collaboration
            editor.on('change', function(instance, changeObj) {
                if (changeObj.origin !== 'remote') {
                    broadcastCodeChange();
                }
                
                clearTimeout(syntaxCheckTimeout);
                syntaxCheckTimeout = setTimeout(checkSyntaxRealTime, 1000);
            });

            editor.on('cursorActivity', function() {
                const cursor = editor.getCursor();
                document.getElementById('status-right').textContent = `Line ${cursor.line + 1}, Col ${cursor.ch + 1}`;
                
                // Broadcast cursor position
                if (socket && currentFile) {
                    socket.emit('cursor_move', {
                        file_id: currentFile.id,
                        cursor_pos: cursor
                    });
                }
            });

            // Auto-completion on typing
            editor.on('inputRead', function(instance, changeObj) {
                if (changeObj.text[0].match(/[a-zA-Z_]/)) {
                    setTimeout(() => {
                        CodeMirror.commands.autocomplete(instance);
                    }, 100);
                }
            });

            loadRepos();
        });

        function generateUserId() {
            return 'user_' + Math.random().toString(36).substr(2, 9);
        }

        function setupSocketListeners() {
            socket.on('user_joined', function(data) {
                updateActiveUsers(data.active_users);
                updateStatus(`${data.user_id} joined the file`);
            });

            socket.on('user_left', function(data) {
                updateActiveUsers(data.active_users);
                updateStatus(`${data.user_id} left the file`);
            });

            socket.on('code_updated', function(data) {
                if (data.user_id !== userId) {
                    const cursor = editor.getCursor();
                    editor.setValue(data.content);
                    editor.setCursor(cursor);
                    updateStatus(`Code updated by ${data.user_id}`);
                }
            });

            socket.on('cursor_updated', function(data) {
                updateOtherCursor(data.user_id, data.cursor_pos);
            });
        }

        function broadcastCodeChange() {
            if (socket && currentFile) {
                socket.emit('code_change', {
                    file_id: currentFile.id,
                    content: editor.getValue(),
                    cursor_pos: editor.getCursor()
                });
            }
        }

        function updateActiveUsers(users) {
            const activeUsersDiv = document.getElementById('active-users');
            let html = '<span>👥 Active Users:</span>';
            
            users.forEach(user => {
                const avatar = user.slice(-2).toUpperCase();
                html += `<div class="user-avatar" title="${user}">${avatar}</div>`;
            });
            
            activeUsersDiv.innerHTML = html;
        }

        function updateOtherCursor(userId, cursorPos) {
            // Remove existing cursor for this user
            const existingMarker = document.querySelector(`[data-user="${userId}"]`);
            if (existingMarker) {
                existingMarker.remove();
            }
            
            // Add new cursor marker
            const marker = document.createElement('div');
            marker.className = 'cursor-marker';
            marker.setAttribute('data-user', userId);
            marker.style.borderColor = getUserColor(userId);
            marker.title = `${userId} cursor`;
            
            try {
                const coords = editor.charCoords(cursorPos, 'local');
                marker.style.left = coords.left + 'px';
                marker.style.top = coords.top + 'px';
                document.querySelector('.CodeMirror').appendChild(marker);
                
                // Remove after 3 seconds of inactivity
                setTimeout(() => {
                    const stillThere = document.querySelector(`[data-user="${userId}"]`);
                    if (stillThere) stillThere.remove();
                }, 3000);
            } catch (e) {
                // Cursor position might be invalid
            }
        }

        function getUserColor(userId) {
            const colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57', '#ff9ff3'];
            const hash = userId.split('').reduce((a, b) => {
                a = ((a << 5) - a) + b.charCodeAt(0);
                return a & a;
            }, 0);
            return colors[Math.abs(hash) % colors.length];
        }

        let syntaxCheckTimeout;
        let currentErrors = [];
        let currentWarnings = [];

        // Initialize CodeMirror with advanced features
        document.addEventListener('DOMContentLoaded', function() {
            editor = CodeMirror.fromTextArea(document.getElementById('code-editor'), {
                mode: 'text/x-csrc',
                theme: 'monokai',
                lineNumbers: true,
                autoCloseBrackets: true,
                matchBrackets: true,
                indentUnit: 4,
                indentWithTabs: false,
                lineWrapping: true,
                extraKeys: {
                    "Ctrl-Space": "autocomplete",
                    "Ctrl-/": "toggleComment",
                    "Ctrl-D": "selectNextOccurrence"
                },
                hintOptions: {
                    completeSingle: false,
                    hint: customHint
                },
                gutters: ["CodeMirror-lint-markers", "CodeMirror-linenumbers"],
                lint: true
            });

            // Real-time syntax checking
            editor.on('change', function() {
                clearTimeout(syntaxCheckTimeout);
                syntaxCheckTimeout = setTimeout(checkSyntaxRealTime, 1000);
            });

            editor.on('cursorActivity', function() {
                const cursor = editor.getCursor();
                document.getElementById('status-right').textContent = `Line ${cursor.line + 1}, Col ${cursor.ch + 1}`;
            });

            // Auto-completion on typing
            editor.on('inputRead', function(instance, changeObj) {
                if (changeObj.text[0].match(/[a-zA-Z_]/)) {
                    setTimeout(() => {
                        CodeMirror.commands.autocomplete(instance);
                    }, 100);
                }
            });

            loadRepos();
        });

        let syntaxCheckTimeout;
        let currentErrors = [];
        let currentWarnings = [];

        // Helper functions
        function generateUserId() {
            return 'user_' + Math.random().toString(36).substr(2, 9);
        }

        function setupSocketListeners() {
            socket.on('user_joined', function(data) {
                updateActiveUsers(data.active_users);
                updateStatus(`${data.user_id} joined the file`);
            });

            socket.on('user_left', function(data) {
                updateActiveUsers(data.active_users);
                updateStatus(`${data.user_id} left the file`);
            });

            socket.on('code_updated', function(data) {
                if (data.user_id !== userId) {
                    const cursor = editor.getCursor();
                    editor.setValue(data.content);
                    editor.setCursor(cursor);
                    updateStatus(`Code updated by ${data.user_id}`);
                }
            });

            socket.on('cursor_updated', function(data) {
                updateOtherCursor(data.user_id, data.cursor_pos);
            });
        }

        function broadcastCodeChange() {
            if (socket && currentFile) {
                socket.emit('code_change', {
                    file_id: currentFile.id,
                    content: editor.getValue(),
                    cursor_pos: editor.getCursor()
                });
            }
        }

        function updateActiveUsers(users) {
            const activeUsersDiv = document.getElementById('active-users');
            let html = '<span>👥 Active Users:</span>';
            
            users.forEach(user => {
                const avatar = user.slice(-2).toUpperCase();
                html += `<div class="user-avatar" title="${user}">${avatar}</div>`;
            });
            
            activeUsersDiv.innerHTML = html;
        }

        function updateOtherCursor(userId, cursorPos) {
            // Remove existing cursor for this user
            const existingMarker = document.querySelector(`[data-user="${userId}"]`);
            if (existingMarker) {
                existingMarker.remove();
            }
            
            // Add new cursor marker
            const marker = document.createElement('div');
            marker.className = 'cursor-marker';
            marker.setAttribute('data-user', userId);
            marker.style.borderColor = getUserColor(userId);
            marker.title = `${userId} cursor`;
            
            try {
                const coords = editor.charCoords(cursorPos, 'local');
                marker.style.left = coords.left + 'px';
                marker.style.top = coords.top + 'px';
                document.querySelector('.CodeMirror').appendChild(marker);
                
                // Remove after 3 seconds of inactivity
                setTimeout(() => {
                    const stillThere = document.querySelector(`[data-user="${userId}"]`);
                    if (stillThere) stillThere.remove();
                }, 3000);
            } catch (e) {
                // Cursor position might be invalid
            }
        }

        function getUserColor(userId) {
            const colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57', '#ff9ff3'];
            const hash = userId.split('').reduce((a, b) => {
                a = ((a << 5) - a) + b.charCodeAt(0);
                return a & a;
            }, 0);
            return colors[Math.abs(hash) % colors.length];
        }
        // Custom autocomplete function
        async function customHint(editor, options) {
            const cursor = editor.getCursor();
            const line = editor.getLine(cursor.line);
            const word = /[\w$]+/.exec(line.slice(0, cursor.ch));
            
            if (!word) return null;
            
            try {
                const code = editor.getValue();
                const language = currentFile ? currentFile.language : 'c';
                
                const response = await fetch('/api/code-completion', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        code: code,
                        cursor_line: cursor.line,
                        cursor_col: cursor.ch,
                        language: language
                    })
                });
                
                const data = await response.json();
                const completions = data.completions || [];
                
                // OS-specific completions
                const osCompletions = getOSCompletions(language, word[0]);
                const allCompletions = [...new Set([...completions, ...osCompletions])];
                
                return {
                    list: allCompletions.map(completion => ({
                        text: completion,
                        displayText: completion,
                        className: 'custom-hint'
                    })),
                    from: CodeMirror.Pos(cursor.line, cursor.ch - word[0].length),
                    to: cursor
                };
            } catch (error) {
                return getOSCompletions(language, word[0]);
            }
        }

        function getOSCompletions(language, prefix) {
            const completions = {
                'c': [
                    'malloc', 'free', 'memcpy', 'memset', 'strlen', 'strcpy', 'strncpy',
                    'printf', 'scanf', 'fopen', 'fclose', 'fread', 'fwrite',
                    'kmalloc', 'kfree', 'printk', 'copy_to_user', 'copy_from_user',
                    'spin_lock', 'spin_unlock', 'mutex_init', 'mutex_lock', 'mutex_unlock',
                    'INIT_LIST_HEAD', 'list_add', 'list_del', 'container_of',
                    'ioremap', 'iounmap', 'request_irq', 'free_irq'
                ],
                'cpp': [
                    'std::unique_ptr', 'std::shared_ptr', 'std::vector', 'std::map',
                    'std::string', 'std::cout', 'std::cin', 'std::endl',
                    'new', 'delete', 'nullptr', 'auto', 'const', 'constexpr'
                ],
                'assembly': [
                    'mov', 'push', 'pop', 'call', 'ret', 'jmp', 'je', 'jne', 'jg', 'jl',
                    'cmp', 'test', 'add', 'sub', 'mul', 'div', 'int', 'nop', 'hlt',
                    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
                    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp'
                ]
            };
            
            const langCompletions = completions[language] || [];
            return langCompletions.filter(comp => 
                comp.toLowerCase().startsWith(prefix.toLowerCase())
            ).slice(0, 10);
        }

        // API Functions
        async function apiCall(url, options = {}) {
            try {
                const response = await fetch(url, {
                    headers: {
                        'Content-Type': 'application/json',
                        ...options.headers
                    },
                    ...options
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'API call failed');
                }
                
                return await response.json();
            } catch (error) {
                updateStatus('Error: ' + error.message);
                throw error;
            }
        }

        async function loadRepos() {
            try {
                const repos = await apiCall('/api/repos');
                const reposList = document.getElementById('repos-list');
                reposList.innerHTML = '';
                
                repos.forEach(repo => {
                    const div = document.createElement('div');
                    div.className = 'repo-item';
                    div.innerHTML = `
                        <strong>${repo.name}</strong>
                        <br><small>${repo.description}</small>
                    `;
                    div.onclick = () => selectRepo(repo);
                    reposList.appendChild(div);
                });
            } catch (error) {
                console.error('Failed to load repos:', error);
            }
        }

        async function selectRepo(repo) {
            currentRepo = repo;
            updateStatus(`Selected repository: ${repo.name}`);
            
            // Highlight selected repo
            document.querySelectorAll('.repo-item').forEach(item => item.classList.remove('active'));
            event.target.classList.add('active');
            
            await loadBranches(repo.id);
        }

        async function loadBranches(repoId) {
            try {
                const branches = await apiCall(`/api/repos/${repoId}/branches`);
                const branchesList = document.getElementById('branches-list');
                branchesList.innerHTML = '';
                
                branches.forEach(branch => {
                    const div = document.createElement('div');
                    div.className = 'branch-item';
                    div.innerHTML = `
                        <strong>${branch.name}</strong>
                        <br><small>Created: ${new Date(branch.created_at).toLocaleDateString()}</small>
                    `;
                    div.onclick = () => selectBranch(branch);
                    branchesList.appendChild(div);
                });
                
                if (branches.length > 0) {
                    selectBranch(branches[0]);
                }
            } catch (error) {
                console.error('Failed to load branches:', error);
            }
        }

        async function selectBranch(branch) {
            currentBranch = branch;
            updateStatus(`Selected branch: ${branch.name}`);
            document.getElementById('current-branch').textContent = branch.name;
            
            // Highlight selected branch
            document.querySelectorAll('.branch-item').forEach(item => item.classList.remove('active'));
            event.target.classList.add('active');
            
            await loadFiles(branch.id);
        }

        async function loadFiles(branchId) {
            try {
                const files = await apiCall(`/api/files?branch_id=${branchId}`);
                const filesList = document.getElementById('files-list');
                filesList.innerHTML = '';
                
                files.forEach(file => {
                    const div = document.createElement('div');
                    div.className = 'file-item';
                    div.innerHTML = `
                        <strong>${file.filename}</strong>
                        <br><small>${file.language.toUpperCase()}</small>
                    `;
                    div.onclick = () => selectFile(file);
                    filesList.appendChild(div);
                });
                
                if (files.length > 0) {
                    selectFile(files[0]);
                }
            } catch (error) {
                console.error('Failed to load files:', error);
            }
        }

        function selectFile(file) {
            // Leave current file room
            if (currentFile && socket) {
                socket.emit('leave_file', { file_id: currentFile.id });
            }
            
            currentFile = file;
            document.getElementById('current-tab').textContent = file.filename;
            document.getElementById('current-language').textContent = file.language.toUpperCase();
            
            // Join new file room
            if (socket) {
                socket.emit('join_file', { file_id: file.id });
            }
            
            // Highlight selected file
            document.querySelectorAll('.file-item').forEach(item => item.classList.remove('active'));
            event.target.classList.add('active');
            
            // Set editor mode based on language
            let mode = 'text/x-csrc';
            if (file.language === 'cpp') {
                mode = 'text/x-c++src';
            } else if (file.language === 'assembly') {
                mode = 'text/x-gas';
            }
            
            editor.setOption('mode', mode);
            editor.setValue(file.content);
            updateStatus(`Opened: ${file.filename}`);
            
            // Check file lock status
            checkFileLock();
        }

        async function checkFileLock() {
            if (!currentFile || !currentBranch) return;
            
            try {
                const response = await apiCall('/api/files/lock', {
                    method: 'POST',
                    body: JSON.stringify({
                        branch_id: currentBranch.id,
                        filename: currentFile.filename
                    })
                });
                
                const lockStatus = document.getElementById('file-lock-status');
                if (response.locked && response.user_id === userId) {
                    isFileOwner = true;
                    lockStatus.innerHTML = '<span style="color: #00ff88;">🔓 You have edit access</span>';
                } else if (!response.locked) {
                    isFileOwner = false;
                    lockStatus.innerHTML = `<span class="file-lock-indicator">🔒 Locked by ${response.locked_by}</span>`;
                }
            } catch (error) {
                console.error('Failed to check file lock:', error);
            }
        }

        async function saveCurrentFile() {
            if (!currentFile || !currentBranch) {
                updateStatus('No file selected');
                return;
            }
            
            if (!isFileOwner) {
                updateStatus('Cannot save: File is locked by another user');
                return;
            }
            
            try {
                const content = editor.getValue();
                const data = {
                    branch_id: currentBranch.id,
                    filename: currentFile.filename,
                    content: content,
                    language: currentFile.language
                };
                
                const response = await apiCall('/api/files', {
                    method: 'POST',
                    body: JSON.stringify(data)
                });
                
                if (response.error && response.error.includes('being edited')) {
                    updateStatus('Save failed: File locked by another user');
                    return;
                }
                
                updateStatus(`Saved: ${currentFile.filename}`);
                
                // Broadcast save to other users
                if (socket) {
                    socket.emit('code_change', {
                        file_id: currentFile.id,
                        content: content,
                        cursor_pos: editor.getCursor()
                    });
                }
                
            } catch (error) {
                console.error('Failed to save file:', error);
                updateStatus('Save failed');
            }
        }

        async function createRepo() {
            const name = document.getElementById('repo-name').value;
            const description = document.getElementById('repo-description').value;
            
            if (!name) {
                alert('Please enter a repository name');
                return;
            }
            
            try {
                const data = { name, description };
                await apiCall('/api/repos', {
                    method: 'POST',
                    body: JSON.stringify(data)
                });
                
                closeModal('createRepoModal');
                loadRepos();
                updateStatus(`Created repository: ${name}`);
            } catch (error) {
                console.error('Failed to create repo:', error);
            }
        }

        async function createBranch() {
            if (!currentRepo) {
                alert('Please select a repository first');
                return;
            }
            
            const name = document.getElementById('branch-name').value;
            
            if (!name) {
                alert('Please enter a branch name');
                return;
            }
            
            try {
                const data = { name };
                await apiCall(`/api/repos/${currentRepo.id}/branches`, {
                    method: 'POST',
                    body: JSON.stringify(data)
                });
                
                closeModal('createBranchModal');
                loadBranches(currentRepo.id);
                updateStatus(`Created branch: ${name}`);
            } catch (error) {
                console.error('Failed to create branch:', error);
            }
        }

        async function uploadRepo() {
            const name = document.getElementById('upload-repo-name').value;
            const file = document.getElementById('repo-file').files[0];
            
            if (!name || !file) {
                alert('Please provide both name and file');
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('file', file);
                formData.append('repo_name', name);
                
                const response = await fetch('/api/upload-repo', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error('Upload failed');
                }
                
                closeModal('uploadModal');
                loadRepos();
                updateStatus(`Uploaded repository: ${name}`);
            } catch (error) {
                console.error('Failed to upload repo:', error);
            }
        }

        async function downloadBranch() {
            if (!currentBranch) {
                alert('Please select a branch first');
                return;
            }
            
            try {
                const response = await fetch(`/api/download/${currentBranch.id}`);
                if (!response.ok) {
                    throw new Error('Download failed');
                }
                
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${currentBranch.name}-${currentBranch.id.slice(0, 8)}.zip`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                updateStatus(`Downloaded branch: ${currentBranch.name}`);
            } catch (error) {
                console.error('Failed to download branch:', error);
            }
        }

        async function checkSyntax() {
            if (!editor) return;
            
            const code = editor.getValue();
            const language = currentFile ? currentFile.language : 'c';
            
            try {
                updateStatus('Running advanced syntax analysis...');
                const result = await apiCall('/api/syntax-check', {
                    method: 'POST',
                    body: JSON.stringify({ code, language })
                });
                
                currentErrors = result.errors || [];
                currentWarnings = result.warnings || [];
                
                displaySyntaxResults(currentErrors, currentWarnings);
                updateStatus('Advanced syntax check complete');
                
                // Update editor with error markers
                updateEditorMarkers(currentErrors, currentWarnings);
                
            } catch (error) {
                console.error('Syntax check failed:', error);
            }
        }

        async function getAIHelp() {
            if (!editor) return;
            
            const code = editor.getValue();
            const language = currentFile ? currentFile.language : 'c';
            const prompt = document.getElementById('ai-prompt').value;
            
            try {
                updateStatus('Getting AI suggestions...');
                const suggestionsDiv = document.getElementById('ai-suggestions');
                suggestionsDiv.innerHTML = '<div class="loading"></div> Getting AI suggestions...';
                
                // Get current syntax errors for context
                const syntaxResult = await apiCall('/api/syntax-check', {
                    method: 'POST',
                    body: JSON.stringify({ code, language })
                });
                
                let errorContext = "";
                if (syntaxResult.errors && syntaxResult.errors.length > 0) {
                    errorContext = syntaxResult.errors.map(err => `Line ${err.line}: ${err.message}`).join('\n');
                }
                
                const result = await apiCall('/api/ai-assist', {
                    method: 'POST',
                    body: JSON.stringify({ code, language, prompt, error_context: errorContext })
                });
                
                suggestionsDiv.innerHTML = `
                    <div class="suggestions">
                        <strong>🤖 AI Suggestions:</strong><br><br>
                        ${result.suggestions}
                    </div>
                `;
                
                updateStatus('AI suggestions ready');
            } catch (error) {
                console.error('AI assistance failed:', error);
                document.getElementById('ai-suggestions').innerHTML = 
                    '<div style="color: #ff6b6b; padding: 10px;">❌ AI service unavailable</div>';
            }
        }

        function createNewFile() {
            const filename = prompt('Enter filename (e.g., kernel.c, boot.asm):');
            if (!filename || !currentBranch) return;
            
            let language = 'c';
            if (filename.endsWith('.cpp') || filename.endsWith('.cxx') || filename.endsWith('.cc')) {
                language = 'cpp';
            } else if (filename.endsWith('.asm') || filename.endsWith('.s')) {
                language = 'assembly';
            }
            
            const newFile = {
                id: Date.now().toString(),
                filename: filename,
                content: '',
                language: language,
                branch_id: currentBranch.id
            };
            
            currentFile = newFile;
            editor.setValue('');
            document.getElementById('current-tab').textContent = filename;
            document.getElementById('current-language').textContent = language.toUpperCase();
            
            updateStatus(`Created new file: ${filename}`);
        }

        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'block';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        function updateStatus(message) {
            document.getElementById('status-left').textContent = message;
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 's':
                        e.preventDefault();
                        saveCurrentFile();
                        break;
                    case 'n':
                        e.preventDefault();
                        createNewFile();
                        break;
                    case 'k':
                        e.preventDefault();
                        checkSyntax();
                        break;
                }
            }
        });

        // Auto-save functionality with conflict resolution
        let autoSaveTimeout;
        
        function setupAutoSave() {
            if (editor) {
                editor.on('change', function() {
                    clearTimeout(autoSaveTimeout);
                    autoSaveTimeout = setTimeout(() => {
                        if (currentFile && currentBranch && isFileOwner) {
                            saveCurrentFile();
                        }
                    }, 5000); // Auto-save after 5 seconds of inactivity
                });
            }
        }

        // Initialize auto-save after editor is ready
        setTimeout(setupAutoSave, 1000);

        // Close modals when clicking outside
        window.onclick = function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        }

        // Initialize with welcome message
        updateStatus('Welcome to The Code Room! Create or select a repository to start coding.');
    </script>
</body>
</html>
'''

# Create templates directory and index.html
@app.before_first_request
def create_templates():
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    with open('templates/index.html', 'w') as f:
        f.write(html_template)

if __name__ == '__main__':
    # Set session user ID if not exists
    @app.before_request
    def before_request():
        if 'user_id' not in session:
            session['user_id'] = str(uuid.uuid4())
    
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
