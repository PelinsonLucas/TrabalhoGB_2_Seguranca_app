# app/routes.py

from flask import render_template, request, flash, redirect, url_for, Blueprint
from app import services

bp = Blueprint('main', __name__)

@bp.route('/', methods=['GET'])
def index():
    """Exibe a calculadora vazia."""
    return render_template('index.html')

@bp.route('/prefill_calculator', methods=['POST'])
def prefill_calculator():
    """Busca uma CVE para preencher a calculadora com métricas."""
    cve_id = request.form.get('cve_id', '').strip()

    if not services.validate_cve_id(cve_id):
        flash('Formato de CVE inválido. Use o formato: CVE-YYYY-NNNN.', 'danger')
        return redirect(url_for('main.index'))

    try:
        nvd_data = services.fetch_cve_details(cve_id)
        cve_info = services.extract_metrics_from_nvd_data(nvd_data)
        
        if not cve_info['has_v4'] and not cve_info['has_v31']:
            flash(f'Não foram encontradas métricas CVSS para a CVE {cve_id}.', 'warning')
            return redirect(url_for('main.index'))
        
        # Log para debug
        print(f"Vetores originais: v3.1={cve_info.get('original_vector_v31')}, v4.0={cve_info.get('original_vector_v4')}")
        print(f"Métricas v3.1: {cve_info.get('metrics_v31')}")
        
        flash(f'Dados da CVE {cve_id} preenchidos com sucesso.', 'success')
        active_version = '4.0' if cve_info['has_v4'] else '3.1'
        
        # Passa as métricas como argumentos de nível superior
        return render_template('index.html', 
                               cve_info=cve_info,
                               metrics_v4=cve_info.get('metrics_v4', {}),
                               metrics_v31=cve_info.get('metrics_v31', {}),
                               active_version=active_version)

    except (ValueError, ConnectionError) as e:
        flash(str(e), 'danger')
        return redirect(url_for('main.index'))

@bp.route('/calculate', methods=['POST'])
def calculate():
    """Calcula a pontuação e preserva o estado do formulário."""
    form_data = request.form
    cvss_version = form_data.get('cvss_version', '4.0')

    if cvss_version == '3.1':
        result, error = services.calculate_v31_score_from_form(form_data)
    else:
        result, error = services.calculate_v4_score_from_form(form_data)
    
    # Recria os dicionários de métricas a partir dos dados do formulário
    repopulated_metrics_v4 = {}
    repopulated_metrics_v31 = {}
    for key, value in form_data.items():
        if key.startswith('v4_'):
            repopulated_metrics_v4[key[3:]] = value
        elif key.startswith('v31_'):
            repopulated_metrics_v31[key[4:]] = value

    # Cria um objeto cve_info apenas para os dados não relacionados às métricas (resumo, etc.)
    cve_info_for_template = {
        'id': form_data.get('cve_id_hidden'),
        'summary': form_data.get('summary_hidden'),
        'has_v4': form_data.get('has_v4') == 'True',
        'has_v31': form_data.get('has_v31') == 'True',
    }
    
    # Se houver um erro, renderiza novamente com os valores que o usuário inseriu
    if error:
        flash(error, 'danger')
        return render_template('index.html', 
                               cve_info=cve_info_for_template,
                               metrics_v4=repopulated_metrics_v4,
                               metrics_v31=repopulated_metrics_v31,
                               active_version=cvss_version)

    # Se o cálculo for bem-sucedido, mostra os resultados e mantém os valores que o usuário inseriu
    return render_template('index.html', 
                           results=result, 
                           cve_info=cve_info_for_template,
                           metrics_v4=repopulated_metrics_v4,
                           metrics_v31=repopulated_metrics_v31,
                           results_version=cvss_version, 
                           active_version=cvss_version)
