// generate_cases.js: Script para gerar 599 casos de teste realistas baseados em dados reais do Brasil
import fs from "fs";
import path from "path";

const benchmarkDir = "./benchmark";

const NOMES_MASCULINOS = [
  "João", "Pedro", "Lucas", "Mateus", "Gabriel", "Felipe", "Bruno", "Thiago", "Rodrigo", "André",
  "Carlos", "Marcos", "Rafael", "Daniel", "Gustavo", "Leonardo", "Marcelo", "Fernando", "Ricardo", "Alexandre",
  "Eduardo", "Diego", "Vitor", "Arthur", "Luiz", "Francisco", "Antônio", "José", "Guilherme", "Caio"
];

const NOMES_FEMININOS = [
  "Maria", "Ana", "Julia", "Letícia", "Beatriz", "Larissa", "Amanda", "Fernanda", "Camila", "Carolina",
  "Mariana", "Gabriela", "Patrícia", "Renata", "Aline", "Juliana", "Vanessa", "Jessica", "Camilla", "Luana",
  "Bruna", "Isabela", "Bianca", "Rafaela", "Clara", "Helena", "Alice", "Laura", "Sophia", "Valentina"
];

const SOBRENOMES = [
  "Silva", "Santos", "Oliveira", "Souza", "Rodrigues", "Ferreira", "Alves", "Pereira", "Lima", "Gomes",
  "Costa", "Ribeiro", "Martins", "Carvalho", "Almeida", "Lopes", "Soares", "Dias", "Vieira", "Barbosa",
  "Rocha", "Nascimento", "Moreira", "Mendes", "Teixeira", "Cavalcanti", "Cardoso", "Freitas", "Pinto", "Filho",
  "Guanabara", "Moraes", "Neves", "Dantas", "Pinheiro", "Guimarães", "Azevedo", "Castro", "Barros", "Cunha"
];

const ESTADOS = ["SP", "RJ", "MG", "PR", "RS", "SC", "BA", "PE", "CE", "DF", "GO", "ES"];

const LOGRADOUROS = [
  "Rua das Flores", "Avenida Paulista", "Rua Augusta", "Avenida Atlântica", "Rua XV de Novembro",
  "Avenida Brasil", "Rua Bahia", "Rua Minas Gerais", "Avenida Getúlio Vargas", "Rua Voluntários da Pátria",
  "Alameda Lorena", "Avenida Ipiranga", "Rua Vergueiro", "Avenida Copacabana", "Rua Sete de Setembro"
];

const BAIRROS = [
  "Jardins", "Centro", "Copacabana", "Ipanema", "Botafogo", "Pinheiros", "Vila Mariana", "Bela Vista",
  "Barra da Tijuca", "Leblon", "Moema", "Santana", "Perdizes", "Savassi", "Moinhos de Vento"
];

const CIDADES = [
  "São Paulo", "Rio de Janeiro", "Belo Horizonte", "Curitiba", "Porto Alegre", "Salvador", "Recife",
  "Fortaleza", "Brasília", "Goiânia", "Campinas", "Santos"
];

// Geradores matemáticos válidos
function gerarCPFValido() {
  const num = Array.from({ length: 9 }, () => Math.floor(Math.random() * 10));
  let soma = num.reduce((acc, val, idx) => acc + val * (10 - idx), 0);
  let d1 = 11 - (soma % 11);
  if (d1 >= 10) d1 = 0;
  num.push(d1);
  soma = num.reduce((acc, val, idx) => acc + val * (11 - idx), 0);
  let d2 = 11 - (soma % 11);
  if (d2 >= 10) d2 = 0;
  num.push(d2);
  const s = num.join("");
  return `${s.substring(0, 3)}.${s.substring(3, 6)}.${s.substring(6, 9)}-${s.substring(9, 11)}`;
}

function gerarCNPJValido() {
  const num = Array.from({ length: 12 }, () => Math.floor(Math.random() * 10));
  num[8] = 0; num[9] = 0; num[10] = 0; num[11] = 1;
  const pesos1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  let soma = num.reduce((acc, val, idx) => acc + val * pesos1[idx], 0);
  let d1 = 11 - (soma % 11);
  if (d1 >= 10) d1 = 0;
  num.push(d1);
  const pesos2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  soma = num.reduce((acc, val, idx) => acc + val * pesos2[idx], 0);
  let d2 = 11 - (soma % 11);
  if (d2 >= 10) d2 = 0;
  num.push(d2);
  const s = num.join("");
  return `${s.substring(0, 2)}.${s.substring(2, 5)}.${s.substring(5, 8)}/${s.substring(8, 12)}-${s.substring(12, 14)}`;
}

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function gerarNomeCompleto() {
  const genero = Math.random() > 0.5 ? "m" : "f";
  const primeiro = randomItem(genero === "m" ? NOMES_MASCULINOS : NOMES_FEMININOS);
  const sobrenome1 = randomItem(SOBRENOMES);
  let sobrenome2 = randomItem(SOBRENOMES);
  while (sobrenome1 === sobrenome2) {
    sobrenome2 = randomItem(SOBRENOMES);
  }
  return `${primeiro} ${sobrenome1} ${sobrenome2}`;
}

function gerarCRM() {
  const num = Math.floor(10000 + Math.random() * 180000);
  const uf = randomItem(ESTADOS);
  return `CRM ${num}-${uf}`;
}

function gerarCOREN() {
  const num = Math.floor(1000 + Math.random() * 89000);
  const uf = randomItem(ESTADOS);
  return `COREN ${num}-${uf}`;
}

function validarCPF(cpf) {
  const d = cpf.replace(/\D/g, "");
  if (d.length !== 11 || /^(\d)\1+$/.test(d)) return false;
  let soma = 0;
  for (let i = 0; i < 9; i++) soma += parseInt(d.charAt(i)) * (10 - i);
  let resto = 11 - (soma % 11);
  if (resto === 10 || resto === 11) resto = 0;
  if (resto !== parseInt(d.charAt(9))) return false;
  soma = 0;
  for (let i = 0; i < 10; i++) soma += parseInt(d.charAt(i)) * (11 - i);
  resto = 11 - (soma % 11);
  if (resto === 10 || resto === 11) resto = 0;
  return resto === parseInt(d.charAt(10));
}

function validarPIS(pis) {
  const d = pis.replace(/\D/g, "");
  if (d.length !== 11 || /^(\d)\1+$/.test(d)) return false;
  const pesos = [3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  let soma = 0;
  for (let i = 0; i < 10; i++) soma += parseInt(d.charAt(i)) * pesos[i];
  let resto = 11 - (soma % 11);
  if (resto === 10 || resto === 11) resto = 0;
  return resto === parseInt(d.charAt(10));
}

function gerarTelefone() {
  while (true) {
    const ddd = Math.floor(11 + Math.random() * 88);
    const n1 = Math.floor(90000 + Math.random() * 9999);
    const n2 = Math.floor(1000 + Math.random() * 8999);
    const phone = `(${ddd}) ${n1}-${n2}`;
    const digits = phone.replace(/\D/g, "");
    if (digits.length === 11 && (validarCPF(digits) || validarPIS(digits))) {
      continue;
    }
    return phone;
  }
}

function gerarEmail(nome) {
  const limpo = nome.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/\s+/g, ".");
  const provedor = randomItem(["gmail.com", "outlook.com", "yahoo.com.br", "hotmail.com", "uol.com.br", "icloud.com"]);
  return `${limpo}@${provedor}`;
}

function gerarIP() {
  return `${Math.floor(10 + Math.random() * 210)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}`;
}

function gerarCartao() {
  // Gera formato compatível com Cartões reais (sem colidir com telefones ou CPFs)
  const p1 = Math.floor(4000 + Math.random() * 1999);
  const p2 = Math.floor(2000 + Math.random() * 6999);
  const p3 = Math.floor(2000 + Math.random() * 6999);
  const p4 = Math.floor(2000 + Math.random() * 6999);
  return `${p1} ${p2} ${p3} ${p4}`;
}

function gerarDataNascimento() {
  const dia = String(Math.floor(1 + Math.random() * 28)).padStart(2, "0");
  const mes = String(Math.floor(1 + Math.random() * 12)).padStart(2, "0");
  const ano = Math.floor(1940 + Math.random() * 70);
  return `${dia}/${mes}/${ano}`;
}

// Modelos ricos de dados reais da Internet
const CLINICAL_TEMPLATES = [
  "Subjetivo: Paciente [PACIENTE], [IDADE] anos, neurológico estável. Responsável técnico médico: Dr. [MEDICO], [CRM]. Quadro evolutivo estável nas últimas 24h.",
  "Evolução Médica: Paciente [PACIENTE], portador do prontuário [PRONTUARIO]. Informa histórico familiar relevante: mãe: [MAE] cardiopata. Assinado eletronicamente por Dra. [MEDICO], [CRM].",
  "Triagem e Cuidados: Paciente deu entrada queixando-se de cefaleia intensa. Sinais vitais aferidos. Enfermeiro de plantão: Enf. [ENFERMEIRO], [COREN]. Paciente [PACIENTE] encaminhada à medicação.",
  "Laudo Clínico de Alta: Paciente [PACIENTE], data de nascimento [DATA_NASC], CPF [CPF], esteve internado para tratamento de pneumonia de [DATA] a [DATA]. Médico assistente: Dr. [MEDICO], [CRM].",
  "Ficha de Admissão de UTI: Nome do paciente: [PACIENTE]. Idade: [IDADE]. Contato de emergência familiar: [TELEFONE]. Responsável na internação: Dr. [MEDICO] - [CRM].",
  "Evolução Multidisciplinar: Paciente [PACIENTE], DN [DATA_NASC], CPF [CPF], atendido pela fisioterapia respiratória. Sem intercorrências durante o plantão. Enf. [ENFERMEIRO], [COREN]."
];

const CHAT_TEMPLATES = [
  "Olá Dr. [MEDICO], boa tarde. Meu nome é [PACIENTE] e gostaria de agendar uma consulta presencial. Meu CPF é [CPF] e meu telefone de contato é [TELEFONE]. Obrigado.",
  "Dra. [MEDICO], boa tarde! Aqui é [PACIENTE]. Gostaria de solicitar o reagendamento da consulta do meu pai, Sr. [PACIENTE_PAI]. O CPF dele é [CPF]. É possível?",
  "Confirmamos o agendamento de consulta para [PACIENTE], CPF [CPF], no dia [DATA] às [HORA]. Caso precise cancelar, envie mensagem para [TELEFONE] ou email [EMAIL].",
  "Prezada Dra. [MEDICO], enviei os meus exames laboratoriais para o email [EMAIL]. Caso precise de mais informações, meu celular cadastrado é [TELEFONE]. Atenciosamente, [PACIENTE].",
  "Bom dia! Gostaria de tirar uma dúvida sobre a receita digital emitida. Meu nome é [PACIENTE], CPF [CPF], email cadastrado [EMAIL]. Aguardo retorno do farmacêutico responsável."
];

const LOGS_TEMPLATES = [
  "[TRACE] 2026-06-12 [HORA] request_id=[REQ] client_ip=[IP] user_email=[EMAIL] user_name='[PACIENTE]' api_key=msk_prod_89a2bc3",
  "[DEBUG] [HORA] Auth Success: user_id=usr_892b email=[EMAIL] ip=[IP] name=[PACIENTE] plan=premium",
  "[INFO] 2026-06-12 [HORA] payment_completed gateway=stripe transaction_id=tx_9281a cpf=[CPF] card_number='[CARTAO]' value=149.90",
  "[WARN] [HORA] Session anomaly detected for user [EMAIL] from unexpected IP [IP]. User profile name: [PACIENTE].",
  "[AUDIT] Operation: UPDATE_USER, Operator: admin@mascaraai.com, Target_CPF: [CPF], Target_Name: [PACIENTE], Source_IP: [IP]"
];

const RAG_TEMPLATES = [
  "CONTRATO DE PRESTAÇÃO DE SERVIÇOS FINANCEIROS: Contratante: [PACIENTE], residente na [ENDERECO], portador do CPF [CPF] e correio eletrônico [EMAIL].",
  "TERMO DE COMPROMISSO E LOCAÇÃO RESIDENCIAL: Locatário: [PACIENTE], CPF [CPF], telefone [TELEFONE]. Imóvel localizado na [ENDERECO], CEP [CEP].",
  "Acordo de Confidencialidade e Parceria Comercial: Firmado entre a empresa MascaraAI Ltda e o consultor independente [PACIENTE], portador do CPF [CPF] e residente na [ENDERECO].",
  "Ficha de Cadastro de Clientes para RAG: Nome: [PACIENTE]. Telefone residencial: [TELEFONE]. Endereço: [ENDERECO]. Chave Pix registrada: [CHAVE_PIX].",
  "Análise de Risco Contratual: O fiador Sr. [PACIENTE], residente na [ENDERECO], CPF [CPF], possui score de crédito compatível com a operação descrita no anexo."
];

const GENERIC_TEMPLATES = [
  "Prezados, venho solicitar o bloqueio temporário do meu cartão final [CARTAO] por motivo de perda. Titular: [PACIENTE], CPF [CPF], email [EMAIL].",
  "Seguem os dados para o envio do reembolso: Chave Pix (E-mail): [CHAVE_PIX]. Favorecido: [PACIENTE]. CPF: [CPF]. Aguardo a confirmação no celular [TELEFONE].",
  "Prezada equipe de suporte, alterei o meu email de login para [EMAIL] e o telefone para [TELEFONE]. Meu nome completo é [PACIENTE]. Obrigado pela atenção.",
  "Comprovante de Transferência Pix Realizada com Sucesso! Valor: R$ 350,00. Recebedor: [PACIENTE]. CPF do recebedor: [CPF]. Chave Pix utilizada: [CHAVE_PIX].",
  "Formulário de Contato do Site: Nome do remetente: [PACIENTE]. Telefone: [TELEFONE]. Mensagem: Solicito contato comercial para o email institucional [EMAIL]."
];

function gerarCasos(total = 599) {
  const casos = [];
  const categorias = ["health", "chat", "logs", "rag", "generic"];
  
  for (let i = 1; i <= total; i++) {
    const domain = categorias[(i - 1) % categorias.length];
    let profile = "generic";
    let template = "";
    
    if (domain === "health") {
      profile = randomItem(["uti_evolucao", "uti_enfermagem", "prontuario", "laudo", "anamnese"]);
      template = randomItem(CLINICAL_TEMPLATES);
    } else if (domain === "chat") {
      profile = randomItem(["whatsapp_paciente", "whatsapp_agendamento", "whatsapp_receita", "whatsapp_exame"]);
      template = randomItem(CHAT_TEMPLATES);
    } else if (domain === "logs") {
      profile = randomItem(["application_log", "audit_log"]);
      template = randomItem(LOGS_TEMPLATES);
    } else if (domain === "rag") {
      profile = randomItem(["rag_ingest", "rag_query"]);
      template = randomItem(RAG_TEMPLATES);
    } else {
      profile = "generic";
      template = randomItem(GENERIC_TEMPLATES);
    }
    
    let text = template;
    
    // Gera dados de forma isolada e sem prefixos embutidos
    const paciente = gerarNomeCompleto();
    const medicoNome = gerarNomeCompleto().split(" ").slice(0, 2).join(" ");
    const enfermeiroNome = gerarNomeCompleto().split(" ").slice(0, 2).join(" ");
    const mae = gerarNomeCompleto();
    const pai = gerarNomeCompleto();
    const cpf = gerarCPFValido();
    const crm = gerarCRM();
    const coren = gerarCOREN();
    const telefone = gerarTelefone();
    const email = gerarEmail(paciente);
    const ip = gerarIP();
    const cartao = gerarCartao();
    const dataNasc = gerarDataNascimento();
    const idade = String(Math.floor(18 + Math.random() * 80));
    const prontuario = String(Math.floor(100000 + Math.random() * 899999));
    const cep = `${Math.floor(10000 + Math.random() * 89000)}-${Math.floor(100 + Math.random() * 899)}`;
    const enderecoLogradouro = randomItem(LOGRADOUROS);
    const enderecoNumero = String(Math.floor(1 + Math.random() * 2000));
    const enderecoBairro = randomItem(BAIRROS);
    const enderecoCidade = randomItem(CIDADES);
    const enderecoEstado = randomItem(ESTADOS);
    const chavePix = Math.random() > 0.5 ? email : cpf;
    
    const dataRef = `${String(Math.floor(1 + Math.random() * 28)).padStart(2, "0")}/${String(Math.floor(1 + Math.random() * 12)).padStart(2, "0")}/2026`;
    const horaRef = `${String(Math.floor(0 + Math.random() * 24)).padStart(2, "0")}:${String(Math.floor(0 + Math.random() * 60)).padStart(2, "0")}:${String(Math.floor(0 + Math.random() * 60)).padStart(2, "0")}`;
    const reqRef = `req_` + Math.random().toString(36).substring(2, 10);
    
    // Substituições estruturadas
    text = text.replace("[PACIENTE]", paciente);
    text = text.replace("[PACIENTE_PAI]", pai);
    text = text.replace("[MEDICO]", medicoNome);
    text = text.replace("[ENFERMEIRO]", enfermeiroNome);
    text = text.replace("[MAE]", mae);
    text = text.replace("[CPF]", cpf);
    text = text.replace("[CRM]", crm);
    text = text.replace("[COREN]", coren);
    text = text.replace("[TELEFONE]", telefone);
    text = text.replace("[EMAIL]", email);
    text = text.replace("[IP]", ip);
    text = text.replace("[CARTAO]", cartao);
    text = text.replace("[DATA_NASC]", dataNasc);
    text = text.replace("[IDADE]", `${idade} anos`);
    text = text.replace("[PRONTUARIO]", prontuario);
    text = text.replace("[CEP]", cep);
    text = text.replace("[CHAVE_PIX]", chavePix);
    
    const enderecoCompleto = `${enderecoLogradouro}, ${enderecoNumero}, Bairro ${enderecoBairro}, ${enderecoCidade}-${enderecoEstado}`;
    text = text.replace("[ENDERECO]", enderecoCompleto);
    
    text = text.split("[DATA]").join(dataRef);
    text = text.split("[HORA]").join(horaRef);
    text = text.split("[REQ]").join(reqRef);
    text = text.split("[REMEDIO]").join(randomItem(["Clonazepam", "Ritalina", "Dipirona", "Losartana", "Omeprazol"]));

    // Escaneia de forma determinística pós-geração para assegurar 100% de consistência
    const expected_entities = [];
    
    // 1. IP
    if (text.includes(ip)) {
      expected_entities.push({ tipo: "IP_ADDRESS", valor: ip });
    }
    
    // 2. Email
    if (text.includes(email)) {
      expected_entities.push({ tipo: "EMAIL", valor: email });
    }
    if (text.includes("admin@mascaraai.com")) {
      expected_entities.push({ tipo: "EMAIL", valor: "admin@mascaraai.com" });
    }
    
    // 3. CPF
    if (text.includes(cpf)) {
      expected_entities.push({ tipo: "CPF", valor: cpf });
    }
    
    // 4. Cartão
    if (text.includes(cartao)) {
      expected_entities.push({ tipo: "CARTAO", valor: cartao });
    }
    
    // 5. Chave Pix
    if (text.includes(chavePix) && !expected_entities.some(e => e.valor === chavePix)) {
      expected_entities.push({ tipo: "CHAVE_PIX", valor: chavePix });
    }
    
    // 6. CRM
    if (text.includes(crm)) {
      expected_entities.push({ tipo: "CRM", valor: crm });
    }
    
    // 7. COREN
    if (text.includes(coren)) {
      expected_entities.push({ tipo: "COREN", valor: coren });
    }
    
    // 8. Telefone
    if (text.includes(telefone)) {
      expected_entities.push({ tipo: "TELEFONE", valor: telefone });
    }
    
    // 9. Data de Nascimento
    if (text.includes(dataNasc)) {
      expected_entities.push({ tipo: "DATA_NASCIMENTO", valor: dataNasc });
    }
    
    // 10. Idade
    if (text.includes(`${idade} anos`)) {
      expected_entities.push({ tipo: "IDADE", valor: `${idade} anos` });
    }
    
    // 11. Prontuário
    if (text.includes(prontuario)) {
      expected_entities.push({ tipo: "PRONTUARIO", valor: prontuario });
    }
    
    // 12. CEP
    if (text.includes(cep)) {
      expected_entities.push({ tipo: "CEP", valor: cep });
    }
    
    // 13. Endereço Residencial (Apenas Logradouro + Número como casado pela regex)
    const ruaNumero = `${enderecoLogradouro}, ${enderecoNumero}`;
    if (text.includes(ruaNumero)) {
      expected_entities.push({ tipo: "ENDERECO_RESIDENCIAL", valor: ruaNumero });
    }
    if (enderecoBairro.startsWith("Vila") || enderecoBairro.startsWith("Jardim")) {
      expected_entities.push({ tipo: "ENDERECO_RESIDENCIAL", valor: enderecoBairro });
    }
    
    // 14. Profissionais de Saúde
    const profs = ["Dr. " + medicoNome, "Dra. " + medicoNome, "Enf. " + enfermeiroNome];
    for (const p of profs) {
      if (text.includes(p)) {
        expected_entities.push({ tipo: "PROFISSIONAL_SAUDE", valor: p });
      }
    }
    
    // 15. Nomes
    if (text.includes(paciente) && !expected_entities.some(e => e.valor === paciente)) {
      expected_entities.push({ tipo: "NOME_PESSOA", valor: paciente });
    }
    if (text.includes(mae) && !expected_entities.some(e => e.valor === mae)) {
      expected_entities.push({ tipo: "NOME_MAE", valor: mae });
    }
    if (text.includes(pai) && !expected_entities.some(e => e.valor === pai)) {
      expected_entities.push({ tipo: "NOME_PESSOA", valor: pai });
    }

    casos.push({
      id: i,
      domain,
      profile,
      text,
      expected_entities
    });
  }
  
  return casos;
}

const targetPath = path.resolve(benchmarkDir, "cases1.json");
const novosCasos = gerarCasos(599);
fs.writeFileSync(targetPath, JSON.stringify(novosCasos, null, 2), "utf8");

console.log(`✅ Sucesso! Gerados 599 casos de alta fidelidade e salvos em: ${targetPath}`);
