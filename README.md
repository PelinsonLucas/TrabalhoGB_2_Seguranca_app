Collecting workspace information# Calculadora CVSS - Trabalho de Segurança de Aplicações

## Descrição

Este projeto implementa uma aplicação web para analisar e calcular pontuações de vulnerabilidades de segurança utilizando os sistemas CVSS (Common Vulnerability Scoring System) nas versões 3.1 e 4.0. A aplicação permite aos usuários buscar informações detalhadas sobre vulnerabilidades (CVEs) através de uma API pública, visualizar suas métricas e calcular pontuações personalizadas.

## Funcionalidades

1. **Busca de CVEs**: Permite ao usuário buscar uma vulnerabilidade pelo seu identificador (ex: CVE-2021-34527).
2. **Exibição de Dados**: Apresenta as informações da vulnerabilidade de forma estruturada, incluindo seu resumo e vetores CVSS originais.
3. **Cálculo de Pontuações**: Calcula pontuações CVSS (v3.1 e v4.0) com base nas métricas fornecidas pela API ou ajustadas pelo usuário.
4. **Visualização de Severidade**: Exibe a classificação qualitativa das pontuações (baixa, média, alta, crítica).

## Segurança da Aplicação

O projeto implementa diversas práticas de segurança para mitigar vulnerabilidades comuns, baseadas nas seguintes CWEs (Common Weakness Enumeration):

### CWE-20: Validação Imprópria de Entrada
- Implementação de validação rigorosa do formato CVE
- Verificação de caracteres especiais para prevenir injeções

### CWE-295: Validação Imprópria de Certificado
- Validação de certificados SSL nas requisições para a API externa
- Tratamento adequado de erros de SSL

### CWE-116: Codificação Imprópria ou Decodificação da Saída
- Sanitização de conteúdo HTML usando a biblioteca Bleach
- Limitação das tags HTML permitidas na exibição de dados

### CWE-352: Cross-Site Request Forgery (CSRF)
- Implementação de proteção CSRF utilizando Flask-WTF
- Inclusão de tokens CSRF em todos os formulários

## Tecnologias Utilizadas

- **Backend**: Flask (Python)
- **Frontend**: HTML, TailwindCSS, JavaScript
- **Bibliotecas**:
  - CVSS: Para cálculo de pontuações de vulnerabilidades
  - Bleach: Para sanitização de conteúdo HTML
  - Requests: Para comunicação com APIs externas

## Requisitos

- Python 3.6+
- Bibliotecas Python (instaláveis via pip):
  - flask
  - flask-wtf
  - requests
  - cvss
  - bleach

## Instalação e Execução

1. Instale as dependências:
```bash
pip install flask flask-wtf requests cvss bleach
```

2. Configure as variáveis de ambiente:
```bash
export SECRET_KEY="chave-secreta-personalizada"
```

3. Execute a aplicação:
```bash
python run.py
```

4. Acesse a aplicação no navegador:
```
http://localhost:5000
```

## Como Usar

1. Na página inicial, digite o identificador de uma CVE no formato "CVE-YYYY-NNNNN" e clique em "Buscar e Preencher".
2. Analise as informações da vulnerabilidade e suas métricas.
3. Alterne entre as versões CVSS 3.1 e 4.0 usando os botões na parte superior do formulário.
4. Ajuste as métricas conforme necessário.
5. Clique em "Calcular Pontuação" para obter os resultados.
6. Visualize a pontuação e severidade da vulnerabilidade.