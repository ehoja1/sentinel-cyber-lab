# SENTINEL — Security Lab

Laboratório web de análise defensiva de logs. O objetivo é oferecer uma interface simples para inspecionar arquivos de texto e identificar padrões que merecem revisão humana.

## Estado atual

**v0.1.0 — protótipo frontend:** dashboard, importação local de `.log`, `.txt` e `.csv` (máximo de 2 MB), regras heurísticas transparentes, filtros de alertas e exportação JSON. Os dados são processados no navegador e não são enviados a um servidor.

> As regras são demonstrativas e podem gerar falsos positivos ou deixar passar eventos relevantes. Um alerta não comprova um incidente.

## Executar no VS Code

1. Abra a pasta `sentinel-cyber-lab` no VS Code.
2. Abra `index.html` no navegador. Recomendado: usar a extensão **Live Server** no VS Code e clicar em **Go Live**.
3. Entre em **Analisador de logs**, clique em **Carregar exemplo** e depois em **Analisar arquivo**.

Não é necessário instalar dependências para esta etapa.

## Estrutura

```text
sentinel-cyber-lab/
├── index.html
├── css/style.css
├── js/app.js
├── samples/security.log
├── backend/       # etapa futura: FastAPI
├── tests/         # testes futuros
├── .gitignore
└── README.md
```

## Roadmap

- [x] Dashboard responsivo e navegação
- [x] Análise local de logs por regras heurísticas
- [x] Filtros de alertas e exportação JSON
- [ ] Backend FastAPI e validação de dados
- [ ] Persistência SQLite para histórico
- [ ] Testes automatizados e CI no GitHub Actions
- [ ] Documentação de regras e formatos suportados

## Segurança e privacidade

Use apenas logs que você tenha autorização para analisar. Esta versão lê os arquivos localmente no navegador. Não inclua segredos, tokens, senhas ou dados pessoais nos exemplos publicados no repositório.

## Licença

A definir antes da primeira publicação pública.
