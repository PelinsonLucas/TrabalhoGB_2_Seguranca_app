# app/routes.py
# Este arquivo contém todas as rotas (endpoints) da aplicação web

from flask import render_template, request, flash, redirect, url_for, Blueprint
from app import services
import re
import bleach

bp = Blueprint('main', __name__)

@bp.route('/', methods=['GET'])
def index():
    """
    Rota principal da aplicação.
    Renderiza a página da aplicação com o formulário de busca de CVE.
    """
    return render_template('index.html')

@bp.route('/prefill_calculator', methods=['POST'])
def prefill_calculator():
    """
    Rota que processa o formulário de busca de CVE.
    1. Recebe o ID da CVE do formulário
    2. Valida o formato do ID
    3. Busca informações da CVE na API do NVD
    4. Extrai métricas CVSS (v3.1 e v4.0) disponíveis
    5. Preenche o formulário com as métricas encontradas
    """
    cve_id = request.form.get('cve_id', '').strip()

    # Validação do formato da CVE (CVE-YYYY-NNNN)
    if not services.validate_cve_id(cve_id) or not validate_user_input(cve_id):
        flash('Formato de CVE inválido ou entrada contém caracteres não permitidos.', 'danger')
        return redirect(url_for('main.index'))

    try:
        # Busca dados da CVE na API externa
        nvd_data = services.fetch_cve_details(cve_id)
        # Extrai e organiza as métricas CVSS encontradas
        cve_info = services.extract_metrics_from_nvd_data(nvd_data)
        
        # Sanitiza o resumo da CVE para prevenir XSS
        cve_info['summary'] = sanitize_html(cve_info['summary'])
        
        # Verifica se foram encontradas métricas CVSS
        if not cve_info['has_v4'] and not cve_info['has_v31']:
            flash(f'Não foram encontradas métricas CVSS para a CVE {cve_id}.', 'warning')
            return redirect(url_for('main.index'))
        
        # Informação de debug para ajudar na depuração
        print(f"Vetores originais: v3.1={cve_info.get('original_vector_v31')}, v4.0={cve_info.get('original_vector_v4')}")
        print(f"Métricas v3.1: {cve_info.get('metrics_v31')}")
        
        flash(f'Dados da CVE {cve_id} preenchidos com sucesso.', 'success')
        # Define a versão ativa com base nas métricas disponíveis
        active_version = '4.0' if cve_info['has_v4'] else '3.1'
        
        # Renderiza a página com as métricas encontradas
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
    """
    Rota que processa o formulário de cálculo CVSS.
    1. Recebe todos os dados do formulário
    2. Determina qual versão CVSS está sendo usada (3.1 ou 4.0)
    3. Calcula a pontuação CVSS correspondente
    4. Preserva o estado dos formulários para permitir ajustes
    5. Exibe os resultados do cálculo
    """
    form_data = request.form
    cvss_version = form_data.get('cvss_version', '4.0')

    # Calcula a pontuação com base na versão CVSS selecionada
    if cvss_version == '3.1':
        result, error = services.calculate_v31_score_from_form(form_data)
    else:
        result, error = services.calculate_v4_score_from_form(form_data)
    
    # Reconstrói as métricas a partir dos dados do formulário para preservar o estado
    repopulated_metrics_v4 = {}
    repopulated_metrics_v31 = {}
    for key, value in form_data.items():
        if key.startswith('v4_'):
            repopulated_metrics_v4[key[3:]] = value
        elif key.startswith('v31_'):
            repopulated_metrics_v31[key[4:]] = value

    # Cria um objeto com os metadados da CVE (sem as métricas)
    cve_info_for_template = {
        'id': form_data.get('cve_id_hidden'),
        'summary': form_data.get('summary_hidden'),
        'has_v4': form_data.get('has_v4') == 'True',
        'has_v31': form_data.get('has_v31') == 'True',
    }
    
    # Se ocorrer algum erro no cálculo, mantém os valores e exibe o erro
    if error:
        flash(error, 'danger')
        return render_template('index.html', 
                               cve_info=cve_info_for_template,
                               metrics_v4=repopulated_metrics_v4,
                               metrics_v31=repopulated_metrics_v31,
                               active_version=cvss_version)

    # Se o cálculo for bem-sucedido, exibe os resultados mantendo os valores nos formulários
    return render_template('index.html', 
                           results=result, 
                           cve_info=cve_info_for_template,
                           metrics_v4=repopulated_metrics_v4,
                           metrics_v31=repopulated_metrics_v31,
                           results_version=cvss_version, 
                           active_version=cvss_version)

def validate_user_input(input_str, max_length=100):
    """
    Valida entrada do usuário para prevenir ataques de injeção.
    """
    if not input_str or len(input_str) > max_length:
        return False
    # Verifica caracteres não permitidos
    if re.search(r'[<>\'";]', input_str):
        return False
    return True

def sanitize_html(html_content):
    """
    Sanitiza conteúdo HTML para prevenir XSS.
    """
    allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li']
    return bleach.clean(html_content, tags=allowed_tags, strip=True)
