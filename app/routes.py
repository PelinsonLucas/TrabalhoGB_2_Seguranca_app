# app/routes.py

from flask import render_template, request, flash, redirect, url_for, Blueprint
from app import services

# Cria um "Blueprint", que é um conjunto de rotas que podem ser registradas na aplicação.
bp = Blueprint('main', __name__)

@bp.route('/', methods=['GET'])
def index():
    """Renderiza a página inicial."""
    # [MITIGAÇÃO CWE-79] O Jinja2 do Flask escapa automaticamente os dados
    return render_template('index.html')

@bp.route('/search', methods=['POST'])
def search_cve():
    """Processa o formulário de busca de CVE."""
    cve_id = request.form.get('cve_id', '').strip()

    if not services.validate_cve_id(cve_id):
        flash('Formato de CVE inválido. Por favor, use o formato: CVE-YYYY-NNNN.', 'danger')
        return redirect(url_for('main.index'))

    try:
        raw_data = services.fetch_cve_details(cve_id)
        cve_data = services.parse_and_score_cve(raw_data)
        
        if not cve_data:
            flash('Não foi possível analisar os dados da CVE recebidos da API.', 'warning')
            return redirect(url_for('main.index'))
            
        return render_template('index.html', cve=cve_data, get_severity=services.get_cvss_severity)

    except (ValueError, ConnectionError) as e:
        flash(str(e), 'danger')
        return redirect(url_for('main.index'))

@bp.route('/recalculate', methods=['POST'])
def recalculate_cvss():
    """Processa o formulário de recálculo de CVSS."""
    original_vector = request.form.get('original_vector')
    
    if not original_vector:
        flash('Vetor CVSS original não encontrado para o recálculo.', 'danger')
        return redirect(url_for('main.index'))
    
    try:
        metrics = {k: v for k, v in request.form.items() if k.isupper()}
        
        recalculated_data = services.recalculate_scores(original_vector, metrics)
        
        # Monta a estrutura de dados para renderizar o template
        cve_data_for_template = {
            'id': request.form.get('cve_id_hidden', 'N/A'),
            'summary': request.form.get('summary_hidden', ''),
            'references': [],
            'cvss_vector_v3': recalculated_data['vector'],
            'cvss_obj': recalculated_data['cvss_obj'],
            'scores': recalculated_data['scores'],
            'recalculated': True
        }
        
        flash('Pontuação CVSS recalculada com sucesso!', 'success')
        return render_template('index.html', cve=cve_data_for_template, get_severity=services.get_cvss_severity)

    except Exception as e:
        flash(f'Erro ao recalcular a pontuação CVSS: {e}', 'danger')
        return redirect(url_for('main.index'))

