"""
Enigma Machine v2.1 - Web Interface
Modern GUI using Flask - compatible with Python 3.14 on macOS
"""

from flask import Flask, render_template_string, request, jsonify, send_file
import base64
import pyperclip
import os
import tempfile
from pathlib import Path
from enigma_machine_aesv2 import (
    SecureEnigmaCrypto,
    FileEncryption,
    PasswordStrength
)

app = Flask(__name__)

# Template HTML
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enigma Machine v2.1</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }

        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .tabs {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }

        .tab-buttons {
            display: flex;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }

        .tab-button {
            flex: 1;
            padding: 20px;
            border: none;
            background: none;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
            color: #6c757d;
        }

        .tab-button:hover {
            background: #e9ecef;
        }

        .tab-button.active {
            background: white;
            color: #667eea;
            border-bottom: 3px solid #667eea;
        }

        .tab-content {
            display: none;
            padding: 30px;
        }

        .tab-content.active {
            display: block;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }

        textarea, input[type="password"], input[type="file"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 14px;
            font-family: 'Monaco', monospace;
            transition: border-color 0.3s;
        }

        textarea:focus, input:focus {
            outline: none;
            border-color: #667eea;
        }

        textarea {
            min-height: 150px;
            resize: vertical;
        }

        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }

        button {
            flex: 1;
            padding: 15px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        .btn-secondary {
            background: #6c757d;
            color: white;
        }

        .btn-secondary:hover {
            background: #5a6268;
        }

        .strength-indicator {
            padding: 10px;
            margin-top: 10px;
            border-radius: 8px;
            font-size: 14px;
            display: none;
        }

        .strength-indicator.show {
            display: block;
        }

        .strength-very-weak { background: #fee; color: #c00; }
        .strength-weak { background: #ffeaa7; color: #d63031; }
        .strength-medium { background: #ffeaa7; color: #e17055; }
        .strength-strong { background: #dfe6e9; color: #00b894; }
        .strength-very-strong { background: #d1f2eb; color: #00b894; }

        .result-box {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border: 2px solid #e9ecef;
            word-break: break-all;
            font-family: 'Monaco', monospace;
            font-size: 12px;
            display: none;
        }

        .result-box.show {
            display: block;
        }

        .status-message {
            margin-top: 15px;
            padding: 12px;
            border-radius: 8px;
            display: none;
        }

        .status-message.show {
            display: block;
        }

        .status-success {
            background: #d1f2eb;
            color: #00b894;
            border: 2px solid #00b894;
        }

        .status-error {
            background: #fee;
            color: #c00;
            border: 2px solid #c00;
        }

        .status-warning {
            background: #ffeaa7;
            color: #d63031;
            border: 2px solid #d63031;
        }

        .footer {
            text-align: center;
            color: white;
            margin-top: 30px;
            opacity: 0.8;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }

        .loading.show {
            display: block;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Enigma Machine v2.1</h1>
            <p>Modern Cryptography with AES-GCM + Argon2id</p>
        </div>

        <div class="tabs">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="switchTab(0)">🔒 Criptografar Mensagem</button>
                <button class="tab-button" onclick="switchTab(1)">🔓 Descriptografar Mensagem</button>
                <button class="tab-button" onclick="switchTab(2)">📁 Criptografar Arquivo</button>
                <button class="tab-button" onclick="switchTab(3)">📂 Descriptografar Arquivo</button>
            </div>

            <!-- Tab 1: Criptografar Mensagem -->
            <div class="tab-content active">
                <div class="form-group">
                    <label>Mensagem:</label>
                    <textarea id="enc-message" placeholder="Digite sua mensagem aqui..."></textarea>
                </div>
                <div class="form-group">
                    <label>Senha:</label>
                    <input type="password" id="enc-password" placeholder="Digite uma senha forte..." oninput="checkPasswordStrength('enc')">
                    <div id="enc-strength" class="strength-indicator"></div>
                </div>
                <div class="button-group">
                    <button class="btn-primary" onclick="encryptMessage()">🔐 CRIPTOGRAFAR</button>
                    <button class="btn-secondary" onclick="copyToClipboard('enc-result')">📋 COPIAR RESULTADO</button>
                </div>
                <div id="enc-status" class="status-message"></div>
                <div id="enc-loading" class="loading">
                    <div class="spinner"></div>
                    <p>Criptografando...</p>
                </div>
                <div id="enc-result" class="result-box"></div>
            </div>

            <!-- Tab 2: Descriptografar Mensagem -->
            <div class="tab-content">
                <div class="form-group">
                    <label>Mensagem Criptografada:</label>
                    <textarea id="dec-message" placeholder="Cole a mensagem criptografada aqui..."></textarea>
                </div>
                <div class="form-group">
                    <label>Senha:</label>
                    <input type="password" id="dec-password" placeholder="Digite a senha...">
                </div>
                <div class="button-group">
                    <button class="btn-primary" onclick="decryptMessage()">🔓 DESCRIPTOGRAFAR</button>
                    <button class="btn-secondary" onclick="pasteFromClipboard('dec-message')">📋 COLAR</button>
                </div>
                <div id="dec-status" class="status-message"></div>
                <div id="dec-loading" class="loading">
                    <div class="spinner"></div>
                    <p>Descriptografando...</p>
                </div>
                <div id="dec-result" class="result-box"></div>
            </div>

            <!-- Tab 3: Criptografar Arquivo -->
            <div class="tab-content">
                <div class="form-group">
                    <label>Arquivo:</label>
                    <input type="file" id="enc-file">
                </div>
                <div class="form-group">
                    <label>Senha:</label>
                    <input type="password" id="enc-file-password" placeholder="Digite uma senha forte..." oninput="checkPasswordStrength('enc-file')">
                    <div id="enc-file-strength" class="strength-indicator"></div>
                </div>
                <button class="btn-primary" onclick="encryptFile()">🔐 CRIPTOGRAFAR ARQUIVO</button>
                <div id="enc-file-status" class="status-message"></div>
                <div id="enc-file-loading" class="loading">
                    <div class="spinner"></div>
                    <p>Criptografando arquivo...</p>
                </div>
            </div>

            <!-- Tab 4: Descriptografar Arquivo -->
            <div class="tab-content">
                <div class="form-group">
                    <label>Arquivo Criptografado:</label>
                    <input type="file" id="dec-file">
                </div>
                <div class="form-group">
                    <label>Senha:</label>
                    <input type="password" id="dec-file-password" placeholder="Digite a senha...">
                </div>
                <button class="btn-primary" onclick="decryptFile()">🔓 DESCRIPTOGRAFAR ARQUIVO</button>
                <div id="dec-file-status" class="status-message"></div>
                <div id="dec-file-loading" class="loading">
                    <div class="spinner"></div>
                    <p>Descriptografando arquivo...</p>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>⚠️ Educational and experimental system • Use established libraries for production</p>
            <p>Developed with Python • Enigma Machine v2.1</p>
        </div>
    </div>

    <script>
        function switchTab(index) {
            const buttons = document.querySelectorAll('.tab-button');
            const contents = document.querySelectorAll('.tab-content');

            buttons.forEach((btn, i) => {
                btn.classList.toggle('active', i === index);
            });

            contents.forEach((content, i) => {
                content.classList.toggle('active', i === index);
            });
        }

        async function checkPasswordStrength(prefix) {
            const password = document.getElementById(`${prefix}-password`).value;
            const strengthDiv = document.getElementById(`${prefix}-strength`);

            if (!password) {
                strengthDiv.classList.remove('show');
                return;
            }

            const response = await fetch('/check-password', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({password})
            });

            const data = await response.json();
            strengthDiv.textContent = data.message;
            strengthDiv.className = `strength-indicator show strength-${data.level}`;
        }

        async function encryptMessage() {
            const message = document.getElementById('enc-message').value;
            const password = document.getElementById('enc-password').value;
            const resultDiv = document.getElementById('enc-result');
            const statusDiv = document.getElementById('enc-status');
            const loadingDiv = document.getElementById('enc-loading');

            if (!message || !password) {
                showStatus('enc', 'warning', '⚠️ Preencha todos os campos!');
                return;
            }

            loadingDiv.classList.add('show');
            resultDiv.classList.remove('show');
            statusDiv.classList.remove('show');

            try {
                const response = await fetch('/encrypt-message', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message, password})
                });

                const data = await response.json();
                loadingDiv.classList.remove('show');

                if (data.success) {
                    resultDiv.textContent = data.result;
                    resultDiv.classList.add('show');
                    showStatus('enc', 'success', '✅ ' + data.message);
                } else {
                    showStatus('enc', 'error', '❌ ' + data.message);
                }
            } catch (error) {
                loadingDiv.classList.remove('show');
                showStatus('enc', 'error', '❌ Erro: ' + error.message);
            }
        }

        async function decryptMessage() {
            const message = document.getElementById('dec-message').value;
            const password = document.getElementById('dec-password').value;
            const resultDiv = document.getElementById('dec-result');
            const statusDiv = document.getElementById('dec-status');
            const loadingDiv = document.getElementById('dec-loading');

            if (!message || !password) {
                showStatus('dec', 'warning', '⚠️ Preencha todos os campos!');
                return;
            }

            loadingDiv.classList.add('show');
            resultDiv.classList.remove('show');
            statusDiv.classList.remove('show');

            try {
                const response = await fetch('/decrypt-message', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message, password})
                });

                const data = await response.json();
                loadingDiv.classList.remove('show');

                if (data.success) {
                    resultDiv.textContent = data.result;
                    resultDiv.classList.add('show');
                    showStatus('dec', 'success', '✅ ' + data.message);
                } else {
                    showStatus('dec', 'error', '❌ ' + data.message);
                }
            } catch (error) {
                loadingDiv.classList.remove('show');
                showStatus('dec', 'error', '❌ Erro: ' + error.message);
            }
        }

        async function encryptFile() {
            const fileInput = document.getElementById('enc-file');
            const password = document.getElementById('enc-file-password').value;
            const statusDiv = document.getElementById('enc-file-status');
            const loadingDiv = document.getElementById('enc-file-loading');

            if (!fileInput.files[0] || !password) {
                showStatus('enc-file', 'warning', '⚠️ Selecione um arquivo e digite uma senha!');
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('password', password);

            loadingDiv.classList.add('show');
            statusDiv.classList.remove('show');

            try {
                const response = await fetch('/encrypt-file', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                loadingDiv.classList.remove('show');

                if (data.success) {
                    showStatus('enc-file', 'success', '✅ ' + data.message);
                    // Download do arquivo
                    window.location.href = '/download/' + data.filename;
                } else {
                    showStatus('enc-file', 'error', '❌ ' + data.message);
                }
            } catch (error) {
                loadingDiv.classList.remove('show');
                showStatus('enc-file', 'error', '❌ Erro: ' + error.message);
            }
        }

        async function decryptFile() {
            const fileInput = document.getElementById('dec-file');
            const password = document.getElementById('dec-file-password').value;
            const statusDiv = document.getElementById('dec-file-status');
            const loadingDiv = document.getElementById('dec-file-loading');

            if (!fileInput.files[0] || !password) {
                showStatus('dec-file', 'warning', '⚠️ Selecione um arquivo e digite uma senha!');
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('password', password);

            loadingDiv.classList.add('show');
            statusDiv.classList.remove('show');

            try {
                const response = await fetch('/decrypt-file', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                loadingDiv.classList.remove('show');

                if (data.success) {
                    showStatus('dec-file', 'success', '✅ ' + data.message);
                    // Download do arquivo
                    window.location.href = '/download/' + data.filename;
                } else {
                    showStatus('dec-file', 'error', '❌ ' + data.message);
                }
            } catch (error) {
                loadingDiv.classList.remove('show');
                showStatus('dec-file', 'error', '❌ Erro: ' + error.message);
            }
        }

        function showStatus(prefix, type, message) {
            const statusDiv = document.getElementById(`${prefix}-status`);
            statusDiv.textContent = message;
            statusDiv.className = `status-message show status-${type}`;
        }

        async function copyToClipboard(elementId) {
            const text = document.getElementById(elementId).textContent;
            if (!text) return;

            try {
                await navigator.clipboard.writeText(text);
                alert('📋 Copiado para clipboard!');
            } catch (err) {
                alert('❌ Erro ao copiar');
            }
        }

        async function pasteFromClipboard(elementId) {
            try {
                const text = await navigator.clipboard.readText();
                document.getElementById(elementId).value = text;
            } catch (err) {
                alert('❌ Erro ao colar');
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.json
    password = data.get('password', '')

    strength, message = PasswordStrength.assess_strength(password)
    entropy = PasswordStrength.calculate_entropy(password)

    levels = {
        "MUITO FRACA": "very-weak",
        "FRACA": "weak",
        "MÉDIA": "medium",
        "FORTE": "strong",
        "MUITO FORTE": "very-strong"
    }

    return jsonify({
        'level': levels.get(strength, 'weak'),
        'message': f"{strength} (entropia: {entropy:.1f} bits) - {message}"
    })

@app.route('/encrypt-message', methods=['POST'])
def encrypt_message():
    try:
        data = request.json
        message = data.get('message', '')
        password = data.get('password', '')

        if not message or not password:
            return jsonify({'success': False, 'message': 'Preencha todos os campos!'})

        if len(password) < 8:
            return jsonify({'success': False, 'message': 'Senha deve ter no mínimo 8 caracteres!'})

        encrypted_data = SecureEnigmaCrypto.encrypt(message, password, show_progress=False)
        encrypted_b64 = base64.b64encode(encrypted_data).decode()

        return jsonify({
            'success': True,
            'result': encrypted_b64,
            'message': 'Mensagem criptografada com sucesso! (Copiada para clipboard)'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/decrypt-message', methods=['POST'])
def decrypt_message():
    try:
        data = request.json
        message = data.get('message', '')
        password = data.get('password', '')

        if not message or not password:
            return jsonify({'success': False, 'message': 'Preencha todos os campos!'})

        encrypted_data = base64.b64decode(message.strip())
        decrypted = SecureEnigmaCrypto.decrypt(encrypted_data, password, show_progress=False)

        return jsonify({
            'success': True,
            'result': decrypted,
            'message': 'Mensagem descriptografada com sucesso!'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/encrypt-file', methods=['POST'])
def encrypt_file_route():
    try:
        file = request.files['file']
        password = request.form['password']

        if not file or not password:
            return jsonify({'success': False, 'message': 'Selecione um arquivo e digite uma senha!'})

        if len(password) < 8:
            return jsonify({'success': False, 'message': 'Senha deve ter no mínimo 8 caracteres!'})

        # Salva arquivo temporário
        temp_dir = tempfile.gettempdir()
        input_path = os.path.join(temp_dir, file.filename)
        output_path = input_path + '.enc'

        file.save(input_path)

        # Criptografa
        FileEncryption.encrypt_file(input_path, output_path, password)

        return jsonify({
            'success': True,
            'filename': os.path.basename(output_path),
            'message': f'Arquivo criptografado com sucesso!'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/decrypt-file', methods=['POST'])
def decrypt_file_route():
    try:
        file = request.files['file']
        password = request.form['password']

        if not file or not password:
            return jsonify({'success': False, 'message': 'Selecione um arquivo e digite uma senha!'})

        # Salva arquivo temporário
        temp_dir = tempfile.gettempdir()
        input_path = os.path.join(temp_dir, file.filename)

        if file.filename.endswith('.enc'):
            output_filename = file.filename[:-4]
        else:
            output_filename = file.filename + '.dec'

        output_path = os.path.join(temp_dir, output_filename)

        file.save(input_path)

        # Descriptografa
        FileEncryption.decrypt_file(input_path, output_path, password)

        return jsonify({
            'success': True,
            'filename': output_filename,
            'message': f'Arquivo descriptografado com sucesso!'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/download/<filename>')
def download_file(filename):
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, filename)
    return send_file(file_path, as_attachment=True, download_name=filename)

def main():
    print("\n" + "="*60)
    print("🔐 Enigma Machine v2.1 - Web Interface")
    print("="*60)
    print("\n✅ Server started!")
    print("🌐 Access: http://127.0.0.1:5000")
    print("\n💡 Press Ctrl+C to stop\n")

    app.run(debug=False, host='127.0.0.1', port=5000)

if __name__ == "__main__":
    main()
