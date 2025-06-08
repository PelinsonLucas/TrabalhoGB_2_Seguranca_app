# app/routes.py

from flask import render_template, request, flash, redirect, url_for, Blueprint
from app import services

bp = Blueprint('main', __name__)

@bp.route('/', methods=['GET'])
def index():
    """Exibe a calculadora vazia."""
    return render_template('index.html')

@bp.route('/prefill', methods=['POST'])
def prefill_calculator():
    """Busca uma CVE para preencher a calculadora."""
    cve_id = request.form.get('cve_id', '').strip()

    if not services.validate_cve_id(cve_id):
        flash('Formato de CVE inválido. Use o formato: CVE-YYYY-NNNN.', 'danger')
        return redirect(url_for('main.index'))

    try:
        nvd_data = services.fetch_cve_details(cve_id)
        metrics, was_mapped = services.get_v4_metrics_from_nvd_data(nvd_data)
        
        if not metrics:
            flash(f'Não foram encontradas métricas CVSS (v4.0 ou v3.1) para a CVE {cve_id}.', 'warning')
            return redirect(url_for('main.index'))
        
        cve_info = {
            'id': nvd_data.get('id'),
            'summary': next((desc['value'] for desc in nvd_data.get('descriptions', []) if desc['lang'] == 'en'), 'Sem resumo disponível.'),
            'metrics': metrics
        }

        if was_mapped:
            flash(f'Dados da CVE {cve_id} preenchidos a partir de CVSS v3.1. Revise os campos que não puderam ser mapeados.', 'info')
        else:
            flash(f'Dados da CVE {cve_id} preenchidos com sucesso.', 'success')
            
        return render_template('index.html', cve_info=cve_info)

    except (ValueError, ConnectionError) as e:
        flash(str(e), 'danger')
        return redirect(url_for('main.index'))

@bp.route('/calculate', methods=['POST'])
def calculate():
    """Calcula a pontuação a partir dos dados do formulário."""
    form_data = request.form
    
    result, error = services.calculate_v4_score_from_form(form_data)
    
    # Recria o objeto cve_info para reexibir os dados no formulário
    cve_info = {
        'id': form_data.get('cve_id_hidden'),
        'summary': form_data.get('summary_hidden'),
        'metrics': form_data
    }
    
    if error:
        flash(error, 'danger')
        return render_template('index.html', cve_info=cve_info)
    
    # A função get_severity não é mais necessária aqui, pois a lógica foi movida para o service
    return render_template('index.html', results=result, cve_info=cve_info)
