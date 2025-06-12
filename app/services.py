# app/services.py
# Este arquivo contém os serviços e funções de negócio da aplicação

import re
import requests
from cvss import CVSS3, CVSS4

# Constantes para API e validação
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
CVE_REGEX = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

def validate_cve_id(cve_id):
    """
    Valida o formato do ID da CVE usando expressão regular.
    O formato válido é: CVE-YYYY-NNNN, onde YYYY é o ano e NNNN é um número sequencial.
    """
    return CVE_REGEX.match(cve_id) is not None

def fetch_cve_details(cve_id):
    """
    Busca os detalhes da CVE na API do NVD com verificação de certificado.
    """
    api_url = NVD_API_URL.format(cve_id.upper())
    try:
        headers = {'User-Agent': 'Trabalho Academico - Analisador de CVE'}
        # Garantir verificação de certificado
        response = requests.get(api_url, headers=headers, timeout=15, verify=True)
        response.raise_for_status()
        data = response.json()
        if data.get('totalResults', 0) == 0:
            raise ValueError(f'A CVE "{cve_id}" não foi encontrada na base de dados do NVD.')
        return data['vulnerabilities'][0]['cve']
    except requests.exceptions.SSLError:
        raise ConnectionError("Erro de validação do certificado SSL. A conexão não é segura.")
    except (requests.exceptions.RequestException, KeyError) as e:
        raise ConnectionError(f'Erro ao buscar ou processar dados da API do NVD: {e}')

def extract_metrics_from_nvd_data(nvd_data):
    """
    Extrai e organiza as métricas CVSS dos dados da CVE.
    
    Processo:
    1. Identifica quais versões CVSS estão disponíveis (v4.0 e/ou v3.1)
    2. Extrai as métricas diretamente dos vetores CVSS
    3. Se apenas a v3.1 estiver disponível, mapeia seus valores para v4.0
       para permitir a visualização/edição em ambos os formatos
    
    Retorna um dicionário com as métricas de cada versão e informações gerais da CVE.
    """
    results = {
        'id': nvd_data.get('id'),
        'summary': next((desc['value'] for desc in nvd_data.get('descriptions', []) if desc['lang'] == 'en'), 'Sem resumo disponível.'),
        'has_v4': False,
        'metrics_v4': {},
        'has_v31': False,
        'metrics_v31': {},
        'original_vector_v31': None,  
        'original_vector_v4': None    
    }
    metrics = nvd_data.get('metrics', {})

    # Função auxiliar para encontrar o vetor primário nos dados da API
    def find_primary_vector(metric_list):
        for metric in metric_list:
            if metric.get('type') == 'Primary':
                return metric['cvssData'].get('vectorString')
        return metric_list[0]['cvssData'].get('vectorString') if metric_list else None

    # Processamento de métricas CVSS v4.0
    if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
        vector = find_primary_vector(metrics['cvssMetricV40'])
        if vector:
            results['has_v4'] = True
            results['original_vector_v4'] = vector
            
            # Extração das métricas do vetor
            v4_metrics = {}
            for part in vector.split('/'):
                if ':' in part and not part.startswith('CVSS'):
                    key, value = part.split(':')
                    v4_metrics[key] = value
                    
            results['metrics_v4'] = v4_metrics

    # Processamento de métricas CVSS v3.1
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        vector = find_primary_vector(metrics['cvssMetricV31'])
        if vector:
            results['has_v31'] = True
            results['original_vector_v31'] = vector
            
            # Extração das métricas do vetor
            v31_metrics = {}
            for part in vector.split('/'):
                if ':' in part and not part.startswith('CVSS'):
                    key, value = part.split(':')
                    v31_metrics[key] = value
                    
            results['metrics_v31'] = v31_metrics

    # Conversão de v3.1 para v4.0 quando apenas v3.1 estiver disponível
    if results['has_v31'] and not results['has_v4']:
        v3_metrics = results['metrics_v31']
        v4_mapped_metrics = {
            'AV': v3_metrics.get('AV', 'N'), 
            'AC': v3_metrics.get('AC', 'L'),
            'PR': v3_metrics.get('PR', 'N'), 
            'AT': 'N',
        }
        
        # Mapeamento de UI (Interface do Usuário)
        v3_ui = v3_metrics.get('UI', 'N')
        if v3_ui == 'N':
            v4_mapped_metrics['UI'] = 'N'
        elif v3_ui == 'R':
            v4_mapped_metrics['UI'] = 'P'  # 'Required' em v3.1 é similar a 'Passive' em v4
        
        # Mapeamento de impacto com base no escopo
        if v3_metrics.get('S') == 'U':  # Scope Unchanged (escopo inalterado)
            v4_mapped_metrics.update({
                'VC': v3_metrics.get('C', 'N'), 
                'VI': v3_metrics.get('I', 'N'), 
                'VA': v3_metrics.get('A', 'N'),
                'SC': 'N', 'SI': 'N', 'SA': 'N'  # Sem impacto em sistemas subsequentes
            })
        else:  # Scope Changed (escopo alterado)
            v4_mapped_metrics.update({
                'VC': v3_metrics.get('C', 'N'), 
                'VI': v3_metrics.get('I', 'N'), 
                'VA': v3_metrics.get('A', 'N'),
                'SC': v3_metrics.get('C', 'N'), 
                'SI': v3_metrics.get('I', 'N'), 
                'SA': v3_metrics.get('A', 'N')
            })
        
        # Inicializa métricas opcionais como não definidas
        all_v4_optional_keys = [
            'E', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA', 
            'S', 'AU', 'R', 'V', 'RE', 'P'
        ]
        for key in all_v4_optional_keys:
            v4_mapped_metrics[key] = 'X'
        
        results['metrics_v4'] = v4_mapped_metrics
        results['has_v4'] = True

    return results

def calculate_v4_score_from_form(form_data):
    """
    Calcula a pontuação CVSS v4.0 a partir dos dados do formulário.
    
    Processo:
    1. Constrói o vetor CVSS a partir dos campos do formulário
    2. Usa a biblioteca CVSS4 para calcular as pontuações
    3. Retorna os resultados ou mensagem de erro
    """
    # Ordem das métricas no vetor CVSS v4.0
    ordered_keys = [
        'AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'E', 'CR', 'IR', 'AR', 
        'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA', 
        'S', 'AU', 'R', 'V', 'RE', 'P'
    ]
    vector_parts = ["CVSS:4.0"]
    
    # Constrói o vetor a partir dos campos do formulário
    for key in ordered_keys:
        value = form_data.get(f'v4_{key}')
        if value and value.strip() and value.strip() != 'X':
            vector_parts.append(f"{key}:{value.strip()}")
            
    vector_string = "/".join(vector_parts)

    try:
        # Calcula as pontuações usando a biblioteca CVSS4
        cvss_obj = CVSS4(vector_string)
        scores = cvss_obj.scores()
        severities = cvss_obj.severities()
        
        # Na CVSS v4.0, apenas a pontuação base é retornada
        base_score = scores[0] if len(scores) > 0 else None
        base_severity = severities[0] if len(severities) > 0 else None
        
        # Organiza os resultados apenas com a pontuação base
        return {
            'vector': cvss_obj.vector,
            'scores': {'base': base_score},
            'severities': {'base': base_severity}
        }, None
    except Exception as e:
        return None, f"Erro ao calcular pontuação CVSS v4.0: {e}. Vetor tentado: '{vector_string}'"

def _get_v31_severity(score):
    """
    Determina a severidade qualitativa de uma pontuação CVSS v3.1.
    
    Classificação:
    - 0.0: Nenhuma
    - 0.1-3.9: Baixa
    - 4.0-6.9: Média
    - 7.0-8.9: Alta
    - 9.0-10.0: Crítica
    """
    if score == 0.0:
        return "Nenhuma"
    elif 0.1 <= score <= 3.9:
        return "Baixa"
    elif 4.0 <= score <= 6.9:
        return "Média"
    elif 7.0 <= score <= 8.9:
        return "Alta"
    elif 9.0 <= score <= 10.0:
        return "Crítica"
    return "N/A"

def calculate_v31_score_from_form(form_data):
    """
    Calcula a pontuação CVSS v3.1 a partir dos dados do formulário.
    
    Processo:
    1. Constrói o vetor CVSS a partir dos campos do formulário
    2. Usa a biblioteca CVSS3 para calcular as pontuações
    3. Retorna os resultados ou mensagem de erro
    """
    # Métricas obrigatórias e opcionais
    base_keys = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
    optional_keys = [
        'E', 'RL', 'RC', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'
    ]
    
    vector_parts = ["CVSS:3.1"]
    
    # Adiciona métricas de base (obrigatórias)
    for key in base_keys:
        value = form_data.get(f'v31_{key}')
        if not value:
            return None, f"Erro: A métrica de base obrigatória '{key}' está em falta no formulário."
        vector_parts.append(f"{key}:{value.strip()}")

    # Adiciona métricas opcionais (se definidas)
    for key in optional_keys:
        value = form_data.get(f'v31_{key}')
        if value and value.strip() and value.strip() != 'X':
            vector_parts.append(f"{key}:{value.strip()}")

    vector_string = "/".join(vector_parts)

    try:
        # Calcula as pontuações usando a biblioteca CVSS3
        cvss_obj = CVSS3(vector_string)
        
        base_score = cvss_obj.base_score
        temporal_score = cvss_obj.temporal_score
        environmental_score = cvss_obj.environmental_score

        # Determina as severidades qualitativas
        base_sev = _get_v31_severity(base_score)
        temporal_sev = _get_v31_severity(temporal_score)
        environmental_sev = _get_v31_severity(environmental_score)

        # Organiza os resultados
        return {
            'vector': cvss_obj.vector,
            'scores': {'base': base_score, 'temporal': temporal_score, 'environmental': environmental_score},
            'severities': {'base': base_sev, 'temporal': temporal_sev, 'environmental': environmental_sev}
        }, None
    except Exception as e:
        return None, f"Erro ao calcular pontuação CVSS v3.1: {e}. Vetor tentado: '{vector_string}'"
