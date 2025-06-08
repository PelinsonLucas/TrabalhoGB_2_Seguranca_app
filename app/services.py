# app/services.py

import re
import requests
from cvss import CVSS3

# Constantes de configuração e segurança
CVE_API_URL = "https://cve.circl.lu/api/cve/{}"
CVE_REGEX = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

def validate_cve_id(cve_id):
    """
    [MITIGAÇÃO CWE-20] Valida o formato do ID da CVE.
    Retorna True se for válido, False caso contrário.
    """
    return CVE_REGEX.match(cve_id) is not None

def fetch_cve_details(cve_id):
    """
    Busca os detalhes de uma CVE em uma API externa.
    Retorna os dados em JSON ou lança uma exceção em caso de erro.
    """
    # [MITIGAÇÃO CWE-918] Garante que a URL é formada de maneira segura
    api_url = CVE_API_URL.format(cve_id.upper())
    
    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()  # Lança uma exceção para status de erro (4xx ou 5xx)
        
        if response.status_code == 200:
            return response.json()
        return None # Caso a resposta seja 200 mas vazia

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            # Re-lança um erro específico para "Não Encontrado"
            raise ValueError(f'A CVE "{cve_id}" não foi encontrada.')
        else:
            # Re-lança outros erros HTTP
            raise ConnectionError(f'Erro na API de CVEs. Status: {e.response.status_code}')
    except requests.exceptions.RequestException as e:
        # Lança um erro para problemas de conexão
        raise ConnectionError(f'Erro de conexão com a API: {e}')

def get_cvss_severity(score):
    """Converte uma pontuação CVSS numérica para uma classificação qualitativa."""
    if score is None: return "N/A"
    if 0.1 <= score <= 3.9: return f"Baixa ({score})"
    if 4.0 <= score <= 6.9: return f"Média ({score})"
    if 7.0 <= score <= 8.9: return f"Alta ({score})"
    if 9.0 <= score <= 10.0: return f"Crítica ({score})"
    return f"Nenhuma ({score})"

def parse_and_score_cve(data):
    """
    Analisa os dados brutos da API e calcula as pontuações CVSS.
    Retorna um dicionário estruturado com as informações da CVE.
    """
    if not data:
        return None
    
    cvss_vector_v3 = data.get('cvss-v3')
    cvss_obj = None
    scores = {'base': None, 'temporal': None, 'environmental': None}
    
    if cvss_vector_v3:
        try:
            cvss_obj = CVSS3(cvss_vector_v3)
            scores['base'] = cvss_obj.base_score
            scores['temporal'] = cvss_obj.temporal_score
            scores['environmental'] = cvss_obj.environmental_score
        except Exception as e:
            print(f"Erro ao parsear o vetor CVSS v3: {e}")
            cvss_vector_v3 = f"Vetor inválido: {cvss_vector_v3}"

    return {
        'id': data.get('id', 'N/A'),
        'summary': data.get('summary', 'Sem resumo disponível.'),
        'references': data.get('references', []),
        'cvss_vector_v3': cvss_vector_v3,
        'cvss_obj': cvss_obj,
        'scores': scores
    }

def recalculate_scores(original_vector, metrics):
    """Recalcula as pontuações CVSS com base nas métricas ambientais/temporais."""
    cvss_obj = CVSS3(original_vector)
    cvss_obj.update_from_dict(metrics)
    return {
        'cvss_obj': cvss_obj,
        'vector': cvss_obj.vector,
        'scores': {
            'base': cvss_obj.base_score,
            'temporal': cvss_obj.temporal_score,
            'environmental': cvss_obj.environmental_score
        }
    }