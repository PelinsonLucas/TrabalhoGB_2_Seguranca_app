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
        # Adiciona um User-Agent para identificação na API
        headers = {'User-Agent': 'Trabalho Academico - Analisador de CVE'}
        response = requests.get(api_url, headers=headers, timeout=15)
        response.raise_for_status()  # Lança uma exceção para respostas com erro (4xx ou 5xx)
        data = response.json()
        if data.get('totalResults', 0) == 0:
            raise ValueError(f'A CVE "{cve_id}" não foi encontrada na base de dados do NVD.')
        return data['vulnerabilities'][0]['cve']
    except (requests.exceptions.RequestException, KeyError) as e:
        # Captura erros de conexão, timeout ou formato de JSON inesperado
        raise ConnectionError(f'Erro ao buscar ou processar dados da API do NVD: {e}')

# --- Função para extrair métricas para preencher a calculadora ---
def get_v4_metrics_from_nvd_data(nvd_data):
    """
    Extrai um dicionário de métricas CVSS v4.0.
    Prioriza dados v4.0 "Primary". Se não existirem, mapeia os dados v3.1 "Primary".
    Retorna o dicionário de métricas e um booleano indicando se foi feito o mapeamento a partir da v3.1.
    """
    metrics = nvd_data.get('metrics', {})

    def find_primary_vector(metric_list):
        """Função auxiliar para encontrar o vetor do score primário."""
        primary_metric = None
        for metric in metric_list:
            if metric.get('type') == 'Primary':
                primary_metric = metric
                break
        
        if not primary_metric and metric_list:
            primary_metric = metric_list[0]
            
        return primary_metric['cvssData'].get('vectorString') if primary_metric else None

    # Prioridade 1: Usar dados CVSS v4.0 nativos
    if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
        vector_string = find_primary_vector(metrics['cvssMetricV40'])
        if vector_string:
            cvss_obj = CVSS4(vector_string)
            all_metrics = {key: value for key, value in cvss_obj.metrics.items()}
            # Garante que todas as métricas possíveis tenham um valor padrão 'X' se não estiverem no vetor
            all_possible_keys = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'E', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA', 'S', 'AU', 'R', 'V', 'RE', 'P']
            for key in all_possible_keys:
                if key not in all_metrics:
                    all_metrics[key] = 'X'
            return all_metrics, False

    # Prioridade 2: Mapear dados CVSS v3.1 para v4.0
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        v3_vector = find_primary_vector(metrics['cvssMetricV31'])
        if v3_vector:
            v3 = CVSS3(v3_vector)
            v3_metrics = v3.metrics
            
            v4_mapped_metrics = {
                'AV': v3_metrics.get('AV', 'X'), 'AC': v3_metrics.get('AC', 'X'),
                'PR': v3_metrics.get('PR', 'X'), 'UI': v3_metrics.get('UI', 'X'),
                'AT': 'N',
            }

            if v3_metrics.get('S') == 'U':
                v4_mapped_metrics.update({'VC': v3_metrics.get('C', 'X'), 'VI': v3_metrics.get('I', 'X'), 'VA': v3_metrics.get('A', 'X'), 'SC': 'N', 'SI': 'N', 'SA': 'N'})
            else:
                v4_mapped_metrics.update({'VC': v3_metrics.get('C', 'X'), 'VI': v3_metrics.get('I', 'X'), 'VA': v3_metrics.get('A', 'X'), 'SC': v3_metrics.get('C', 'X'), 'SI': v3_metrics.get('I', 'X'), 'SA': v3_metrics.get('A', 'X')})
            
            # As métricas restantes recebem o valor padrão "Não Definido"
            for metric in ['E', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA', 'S', 'AU', 'R', 'V', 'RE', 'P']:
                v4_mapped_metrics[metric] = 'X'
                
            return v4_mapped_metrics, True

    return None, False

# --- Função de Cálculo ---
def calculate_v4_score_from_form(form_data):
    """
    Constrói um vetor CVSS v4.0 a partir de todos os dados do formulário e calcula as pontuações.
    """
    # Ordem das chaves conforme a especificação CVSS v4.0 para a construção correta do vetor
    ordered_keys = [
        # Base
        'AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 
        # Threat
        'E', 
        # Environmental
        'CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA', 
        # Supplemental
        'S', 'AU', 'R', 'V', 'RE', 'P'
    ]
    
    vector_parts = ["CVSS:4.0"]
    for key in ordered_keys:
        value = form_data.get(key)
        # Adiciona ao vetor apenas se o valor não for 'X' (Não Definido), exceto para métricas obrigatórias
        if value and (value != 'X' or key in ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']):
            vector_parts.append(f"{key}:{value}")
    
    vector_string = "/".join(vector_parts)
    
    try:
        cvss_obj = CVSS4(vector_string)
        
        scores_list = cvss_obj.scores()
        severities_list = cvss_obj.severities()

        severity_map = {
            'None': {'class': 'none', 'name': 'Nenhuma'}, 'Low': {'class': 'low', 'name': 'Baixa'},
            'Medium': {'class': 'medium', 'name': 'Média'}, 'High': {'class': 'high', 'name': 'Alta'},
            'Critical': {'class': 'critical', 'name': 'Crítica'}
        }

        base_score = scores_list[0] if len(scores_list) > 0 else 0.0
        threat_score = scores_list[1] if len(scores_list) > 1 else None
        environmental_score = scores_list[2] if len(scores_list) > 2 else None

        base_sev_info = severity_map.get(severities_list[0]) if len(severities_list) > 0 else severity_map['None']
        threat_sev_info = severity_map.get(severities_list[1]) if len(severities_list) > 1 else severity_map['None']
        env_sev_info = severity_map.get(severities_list[2]) if len(severities_list) > 2 else severity_map['None']

        return {
            'vector': cvss_obj.vector,
            'base': {'score': base_score, 'severity': base_sev_info},
            'threat': {'score': threat_score, 'severity': threat_sev_info},
            'environmental': {'score': environmental_score, 'severity': env_sev_info}
        }, None
    except Exception as e:
        error_message = f"Erro ao calcular com o vetor fornecido: {e}. Vetor tentado: '{vector_string}'"
        return None, error_message
