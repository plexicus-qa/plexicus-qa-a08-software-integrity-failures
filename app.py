from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import pickle
import base64
import yaml
import urllib.request
import importlib.util
import tempfile
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///plugins.db'
app.config['SECRET_KEY'] = 'supersecret'
db = SQLAlchemy(app)


class Plugin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    source_url = db.Column(db.String(255))
    version = db.Column(db.String(20))
    verified = db.Column(db.Boolean, default=False)


with app.app_context():
    db.create_all()
    if not Plugin.query.first():
        db.session.add(Plugin(name='csv-exporter', source_url='http://plugins.example.com/csv-exporter.py', version='1.0.0', verified=False))
        db.session.add(Plugin(name='pdf-renderer', source_url='http://plugins.example.com/pdf-renderer.py', version='2.1.0', verified=False))
        db.session.commit()

# VULNERABILITY: Insecure Deserialization - pickle.loads() on user-controlled
# base64 blob with no signature/integrity check. A crafted pickle payload can
# execute arbitrary code on the server via __reduce__.
@app.route('/api/load-profile', methods=['POST'])
def load_profile():
    data = request.get_json()
    blob = data.get('profile', '')
    try:
        raw = base64.b64decode(blob)
        profile = pickle.loads(raw)  # no integrity/signature check
        return jsonify({'message': 'profile loaded', 'profile': str(profile)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# VULNERABILITY: Unsafe YAML deserialization - yaml.load() (not safe_load)
# allows instantiation of arbitrary Python objects/tags from user input.
@app.route('/api/import-config', methods=['POST'])
def import_config():
    yaml_text = request.data.decode('utf-8')
    try:
        config = yaml.load(yaml_text, Loader=yaml.Loader)  # unsafe loader
        return jsonify({'message': 'config imported', 'config': str(config)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# VULNERABILITY: Unsigned auto-update - fetches a "plugin" from a
# client-supplied URL and imports/executes it with no signature or
# checksum verification whatsoever.
@app.route('/api/update', methods=['POST'])
def update_plugin():
    data = request.get_json()
    name = data.get('name', 'plugin')
    url = data.get('url', '')
    try:
        with urllib.request.urlopen(url) as response:
            code = response.read()

        tmp_dir = tempfile.gettempdir()
        tmp_path = os.path.join(tmp_dir, f'{name}_update.py')
        with open(tmp_path, 'wb') as f:
            f.write(code)  # no checksum, no signature check

        spec = importlib.util.spec_from_file_location(name, tmp_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # executes remote code unconditionally

        plugin = Plugin.query.filter_by(name=name).first()
        if plugin:
            plugin.source_url = url
            plugin.verified = True  # marked verified without ever verifying anything
        else:
            plugin = Plugin(name=name, source_url=url, version='latest', verified=True)
            db.session.add(plugin)
        db.session.commit()

        return jsonify({'message': f'plugin {name} updated and loaded from {url}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# VULNERABILITY: Unrestricted eval() on user-supplied formula string.
@app.route('/api/calculate', methods=['POST'])
def calculate():
    data = request.get_json()
    formula = data.get('formula', '')
    try:
        result = eval(formula)  # arbitrary code execution
        return jsonify({'formula': formula, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/plugins', methods=['GET'])
def list_plugins():
    plugins = Plugin.query.all()
    return jsonify([{
        'id': p.id, 'name': p.name, 'source_url': p.source_url,
        'version': p.version, 'verified': p.verified
    } for p in plugins])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5008)
