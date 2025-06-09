# app/services.py

import re
import requests
from cvss import CVSS3, CVSS4

# --- Constantes ---
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
CVE_REGEX = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

# --- Funções de Validação e Fetch ---
def validate_cve_id(cve_id):
    """Valida o formato do ID da CVE."""
    return CVE_REGEX.match(cve_id) is not None

def fetch_cve_details(cve_id):
    """Busca os detalhes da CVE usando a API do NVD."""
    api_url = NVD_API_URL.format(cve_id.upper())
    try:
        headers = {'User-Agent': 'Trabalho Academico - Analisador de CVE'}
        response = requests.get(api_url, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        if data.get('totalResults', 0) == 0:
            raise ValueError(f'A CVE "{cve_id}" não foi encontrada na base de dados do NVD.')
        return data['vulnerabilities'][0]['cve']
    except (requests.exceptions.RequestException, KeyError) as e:
        raise ConnectionError(f'Erro ao buscar ou processar dados da API do NVD: {e}')

# --- Extração de Métricas ---
def extract_metrics_from_nvd_data(nvd_data):
    """
    Extrai todas as métricas CVSS v4.0 e v3.1 disponíveis.
    Se apenas a v3.1 existir, mapeia os valores para criar uma base para a v4.0.
    """
    results = {
        'id': nvd_data.get('id'),
        'summary': next((desc['value'] for desc in nvd_data.get('descriptions', []) if desc['lang'] == 'en'), 'Sem resumo disponível.'),
        'has_v4': False,
        'metrics_v4': {},
        'has_v31': False,
        'metrics_v31': {},
        'original_vector_v31': None,  # Armazenar vetor original
        'original_vector_v4': None    # Armazenar vetor original
    }
    metrics = nvd_data.get('metrics', {})

    def find_primary_vector(metric_list):
        for metric in metric_list:
            if metric.get('type') == 'Primary':
                return metric['cvssData'].get('vectorString')
        return metric_list[0]['cvssData'].get('vectorString') if metric_list else None

    # Etapa 1: Processar métricas CVSS v4.0, se existirem
    if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
        vector = find_primary_vector(metrics['cvssMetricV40'])
        if vector:
            results['has_v4'] = True
            results['original_vector_v4'] = vector
            
            # Extrair métricas diretamente do vetor (maneira mais confiável)
            v4_metrics = {}
            for part in vector.split('/'):
                if ':' in part and not part.startswith('CVSS'):
                    key, value = part.split(':')
                    v4_metrics[key] = value
                    
            results['metrics_v4'] = v4_metrics

    # Etapa 2: Processar métricas CVSS v3.1, se existirem
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        vector = find_primary_vector(metrics['cvssMetricV31'])
        if vector:
            results['has_v31'] = True
            results['original_vector_v31'] = vector
            
            # Extrair métricas diretamente do vetor (maneira mais confiável)
            v31_metrics = {}
            for part in vector.split('/'):
                if ':' in part and not part.startswith('CVSS'):
                    key, value = part.split(':')
                    v31_metrics[key] = value
                    
            results['metrics_v31'] = v31_metrics

    # Etapa 3: Se apenas a v3.1 existir, mapear para a v4.0 para permitir o cálculo
    if results['has_v31'] and not results['has_v4']:
        v3_metrics = results['metrics_v31']
        v4_mapped_metrics = {
            'AV': v3_metrics.get('AV', 'N'), 
            'AC': v3_metrics.get('AC', 'L'),
            'PR': v3_metrics.get('PR', 'N'), 
            'AT': 'N',
        }
        
        # Mapear UI de v3.1 para v4
        v3_ui = v3_metrics.get('UI', 'N')
        if v3_ui == 'N':
            v4_mapped_metrics['UI'] = 'N'
        elif v3_ui == 'R':
            v4_mapped_metrics['UI'] = 'P'  # 'Required' em v3.1 é mais próximo de 'Passive' em v4
        
        # Determinar o impacto com base no escopo
        if v3_metrics.get('S') == 'U':  # Scope Unchanged
            v4_mapped_metrics.update({
                'VC': v3_metrics.get('C', 'N'), 
                'VI': v3_metrics.get('I', 'N'), 
                'VA': v3_metrics.get('A', 'N'),
                'SC': 'N', 'SI': 'N', 'SA': 'N'  # Sem impacto em sistemas subsequentes
            })
        else:  # Scope Changed (S:C)
            v4_mapped_metrics.update({
                'VC': v3_metrics.get('C', 'N'), 
                'VI': v3_metrics.get('I', 'N'), 
                'VA': v3_metrics.get('A', 'N'),
                'SC': v3_metrics.get('C', 'N'), 
                'SI': v3_metrics.get('I', 'N'), 
                'SA': v3_metrics.get('A', 'N')
            })
        
        # Deixar métricas opcionais como não definidas
        all_v4_optional_keys = [
            'E', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA', 
            'S', 'AU', 'R', 'V', 'RE', 'P'
        ]
        for key in all_v4_optional_keys:
            v4_mapped_metrics[key] = 'X'
        
        results['metrics_v4'] = v4_mapped_metrics
        results['has_v4'] = True

    return results

# --- Funções de Cálculo ---
def calculate_v4_score_from_form(form_data):
    """Constrói um vetor CVSS v4.0 e calcula as pontuações."""
    ordered_keys = [
        'AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'E', 'CR', 'IR', 'AR', 
        'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA', 
        'S', 'AU', 'R', 'V', 'RE', 'P'
    ]
    vector_parts = ["CVSS:4.0"]
    for key in ordered_keys:
        value = form_data.get(f'v4_{key}')
        if value and value.strip() and value.strip() != 'X':
            vector_parts.append(f"{key}:{value.strip()}")
            
    vector_string = "/".join(vector_parts)

    try:
        cvss_obj = CVSS4(vector_string)
        scores = cvss_obj.scores()
        severities = cvss_obj.severities()
        return {
            'vector': cvss_obj.vector,
            'scores': {'base': scores[0], 'threat': scores[1] if len(scores) > 1 else None, 'environmental': scores[2] if len(scores) > 2 else None},
            'severities': {'base': severities[0], 'threat': severities[1] if len(severities) > 1 else None, 'environmental': severities[2] if len(severities) > 2 else None}
        }, None
    except Exception as e:
        return None, f"Erro ao calcular pontuação CVSS v4.0: {e}. Vetor tentado: '{vector_string}'"

def _get_v31_severity(score):
    """Função auxiliar para determinar a severidade de uma pontuação CVSS v3.1."""
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
    """Constrói um vetor CVSS v3.1 e calcula as pontuações."""
    ordered_keys = [
        'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', # Base
        'E', 'RL', 'RC', # Temporal
        'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA' # Environmental
    ]
    vector_parts = ["CVSS:3.1"]
    
    base_keys = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
    for key in base_keys:
        value = form_data.get(f'v31_{key}')
        if not value:
            return None, f"Erro: A métrica de base obrigatória '{key}' está em falta no formulário."
        vector_parts.append(f"{key}:{value.strip()}")

    optional_keys = [
        'E', 'RL', 'RC', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'
    ]
    for key in optional_keys:
        value = form_data.get(f'v31_{key}')
        if value and value.strip() and value.strip() != 'X':
            vector_parts.append(f"{key}:{value.strip()}")

    vector_string = "/".join(vector_parts)

    try:
        cvss_obj = CVSS3(vector_string)
        
        base_score = cvss_obj.base_score
        temporal_score = cvss_obj.temporal_score
        environmental_score = cvss_obj.environmental_score

        base_sev = _get_v31_severity(base_score)
        temporal_sev = _get_v31_severity(temporal_score)
        environmental_sev = _get_v31_severity(environmental_score)

        return {
            'vector': cvss_obj.vector,
            'scores': {'base': base_score, 'temporal': temporal_score, 'environmental': environmental_score},
            'severities': {'base': base_sev, 'temporal': temporal_sev, 'environmental': environmental_sev}
        }, None
    except Exception as e:
        return None, f"Erro ao calcular pontuação CVSS v3.1: {e}. Vetor tentado: '{vector_string}'"
