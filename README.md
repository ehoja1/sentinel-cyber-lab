# SENTINEL Cyber Lab

**Análise defensiva de logs de segurança com Python e FastAPI.**

O SENTINEL é um laboratório de cibersegurança defensiva desenvolvido para analisar eventos de segurança, identificar padrões suspeitos em logs e apresentar os resultados por meio de uma API REST local.

> **Status:** Em desenvolvimento — versão 0.2.0

---

## Visão geral

O SENTINEL tem como objetivo tornar a análise inicial de logs de segurança mais simples, organizada e reproduzível. O projeto está sendo desenvolvido de forma incremental, com foco em legibilidade, confiabilidade e boas práticas de engenharia de software.

## Funcionalidades atuais

- API REST construída com FastAPI.
- Endpoint de saúde para verificar a disponibilidade do serviço.
- Análise de logs enviados em texto.
- Identificação de falhas e sucessos de autenticação SSH por padrões de texto.
- Detecção de determinados erros HTTP em linhas de log compatíveis.
- Agrupamento de tentativas de autenticação falhas por endereço IP.
- Documentação interativa da API via Swagger UI.

**Observação:** a detecção é baseada em padrões conhecidos. Os resultados são indicadores para investigação, não uma confirmação definitiva de atividade maliciosa.

## Tecnologias

| Tecnologia | Finalidade |
|---|---|
| Python | Linguagem principal |
| FastAPI | API REST |
| Uvicorn | Servidor ASGI |
| Pydantic | Validação de dados da API |
| pytest | Testes automatizados planejados/em desenvolvimento |
| Git e GitHub | Controle de versão e hospedagem do código |

## Estrutura do projeto

```text
sentinel-cyber-lab/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── analyzer.py
│   │   └── database.py
│   ├── tests/
│   └── requirements.txt
├── css/
│   └── style.css
├── js/
│   └── app.js
├── samples/
│   └── security.log
├── index.html
├── .gitignore
└── README.md
```

A estrutura representa a organização planejada do projeto; alguns componentes podem estar em desenvolvimento.

## Requisitos

- Python instalado.
- Git instalado.
- Windows PowerShell, terminal do VS Code ou terminal compatível.

## Instalação local

Clone o repositório:

```bash
git clone https://github.com/ehoja1/sentinel-cyber-lab.git
cd sentinel-cyber-lab
```

Crie um ambiente virtual:

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Instale as dependências:

```powershell
python -m pip install -r backend/requirements.txt
```

Inicie a API a partir da raiz do projeto:

```powershell
python -m uvicorn backend.app.main:app --reload
```

O servidor local estará disponível em `http://127.0.0.1:8000`.

## Endpoints

| Método | Endpoint | Descrição |
|---|---|---|
| `GET` | `/` | Informações básicas da API |
| `GET` | `/health` | Verificação de saúde do serviço |
| `POST` | `/analyze` | Análise de logs enviados em texto |

### Documentação interativa

Com o servidor iniciado, acesse:

- Swagger UI: `http://127.0.0.1:8000/docs`
- OpenAPI: `http://127.0.0.1:8000/openapi.json`

### Exemplo de análise

Envie uma requisição `POST` para `/analyze` com o seguinte corpo JSON:

```json
{
  "text": "Failed password for admin from 192.168.1.50 port 2200 ssh2\nAccepted password for joao from 192.168.1.20 port 2200 ssh2"
}
```

A resposta contém os eventos reconhecidos, a quantidade de linhas analisadas e um agrupamento das falhas de autenticação por IP.

Os resultados dependem dos padrões implementados no analisador. Logs em formatos diferentes podem não ser reconhecidos.

## Segurança e uso responsável

- Utilize o SENTINEL somente com logs próprios ou cujo acesso e análise você esteja autorizado a realizar.
- Trate endereços IP, nomes de usuário e trechos de log como possíveis dados sensíveis.
- Não envie segredos, tokens, senhas ou informações pessoais desnecessárias.
- Um alerta não prova, isoladamente, que houve um ataque.
- A versão atual é um projeto em desenvolvimento, não um SIEM completo nem uma solução de monitoramento de produção.

## Roadmap

- [ ] Ampliar e testar as regras de detecção.
- [ ] Criar uma suíte de testes automatizados.
- [ ] Melhorar a validação e o tratamento de entradas inválidas.
- [ ] Desenvolver um dashboard para visualizar eventos e alertas.
- [ ] Implementar persistência e histórico de análises.
- [ ] Adicionar exportação de relatórios.
- [ ] Configurar integração contínua no GitHub Actions.

## Contribuição

Sugestões e contribuições são bem-vindas. Para propor mudanças:

1. Faça um fork do repositório.
2. Crie uma branch para sua alteração.
3. Execute os testes disponíveis.
4. Envie um pull request com uma descrição objetiva.

## Licença

A licença ainda precisa ser definida. Até que um arquivo de licença seja incluído no repositório, não presuma que o código está licenciado para redistribuição ou uso irrestrito.

---

Desenvolvido como projeto de estudo e laboratório de cibersegurança defensiva.