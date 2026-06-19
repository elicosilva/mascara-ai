"""
MascaraAI — NER Server v3.0 (Otimizado)
=======================================

Decisões implementadas:
1. [v3-A] Motor principal: BERTimbau-leNER exportado para ONNX INT8.
2. [v3-B] Sessão ONNX carregada UMA VEZ no startup. Nunca por request.
3. [v3-C] Concorrência: Semaphore(2) e ThreadPoolExecutor(max_workers=1) para CPU single-core de VPS.
4. [v3-D] Cache SHA-256, TTL 24h, nunca armazena texto — só resultado.
5. [v3-E] Circuit breaker: se CPU > 85% por 3 checks consecutivos, retorna lista vazia.
6. [v3-F] Warmup: 5 inferências sintéticas no startup.
7. [v3-G] Chunking corrigido: textos de até 20.000 chars divididos em chunks de no máximo 2.000 chars (safe limit para 512 tokens).
8. [v3-H] Filtros pós-inferência.
9. [v3-I] Capitalização Virtual: Se o texto for 100% lowercase, aplica Title Case para o BERT cased detectar, e depois restaura a caixa baixa no retorno para compatibilidade com o Worker.
"""

import os
import re
import json
import time
import hashlib
import asyncio
import logging
import psutil
from collections import OrderedDict
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor

import numpy as np
from fastapi import FastAPI, Request, HTTPException
from transformers import AutoTokenizer
import onnxruntime as ort

import json as _json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("mascaraai")

# ──────────────────────────────────────────────────────────────
# CONFIGURAÇÃO
# ──────────────────────────────────────────────────────────────

MODEL_ONNX  = os.getenv("NER_MODEL_ONNX",  "ner_model_int8.onnx")
MODEL_HF_ID = os.getenv("NER_MODEL_HF",    "marquesafonso/bertimbau-large-ner-total")

try:
    _ID2LABEL = {int(k): v for k, v in _json.loads(open("/opt/mascaraai/id2label.json").read()).items()}
except Exception:
    try:
        config_path = os.path.join(os.path.dirname(MODEL_ONNX), "config.json")
        if os.path.exists(config_path):
            with open(config_path) as f:
                _ID2LABEL = {int(k): v for k, v in _json.load(f)["id2label"].items()}
        else:
            _ID2LABEL = {}
    except Exception:
        _ID2LABEL = {}

logger.info(f"Loaded label map size: {len(_ID2LABEL)} entries")
MAX_CHARS   = int(os.getenv("NER_MAX_CHARS",  "20000")) # Permite receber textos maiores
MAX_CHUNK_CHARS = 2000                                 # Limite seguro para 512 tokens do BERT
CACHE_SIZE  = int(os.getenv("NER_CACHE_SIZE", "256"))
CPU_LIMIT   = float(os.getenv("NER_CPU_LIMIT", "85.0"))

LABEL_MAP = {
    "PESSOA":      "NOME_PESSOA",
    "ORGANIZACAO": "EMPRESA",
    "LOCAL":       "ENDERECO_RESIDENCIAL",
    "TEMPO":       "DATA_NASCIMENTO",
    "OUTRO":       "OUTRO_IDENTIFICADOR",
    "CRM":         "PROFISSIONAL_SAUDE",
    "COREN":       "PROFISSIONAL_SAUDE",
    "CRP":         "PROFISSIONAL_SAUDE",
    "CRO":         "PROFISSIONAL_SAUDE",
    "CRF":         "PROFISSIONAL_SAUDE",
}

TIPOS_BLOQUEADOS = {
    "VALOR", "ABSTRACCAO", "ACONTECIMENTO", "COISA", "OBRA",
    "OUTRO_IDENTIFICADOR",
}

# ──────────────────────────────────────────────────────────────
# FILTROS PÓS-INFERÊNCIA
# ──────────────────────────────────────────────────────────────

VALORES_IGNORADOS = {
    "admissao", "admissão", "demissao", "demissão",
    "ativo", "inativo", "pendente", "cancelado",
    "aprovado", "rejeitado", "processando",
    "sim", "nao", "não", "yes", "no",
    "true", "false", "null", "none",
    "masculino", "feminino", "outro",
    "solteiro", "casado", "divorciado", "viuvo", "viúvo",
    "entrada", "saida", "saída",
    "pix", "ted", "doc", "boleto",
    "janeiro", "fevereiro", "março", "abril", "maio", "junho",
    "julho", "agosto", "setembro", "outubro", "novembro", "dezembro",
    "estável", "estavel", "ausente", "presente",
    "normal", "alterado", "alterada",
    "negativo", "positivo", "reagente",
    "hipertensão", "hipertensao", "diabetes", "diabético", "diabetico",
    "retorno", "internação", "internacao", "alta", "obito", "óbito",
}

SIGLAS_DOCUMENTOS = {
    "CPF", "CNPJ", "RG", "CNH", "PIS", "NIS",
    "OAB", "CRM", "CREA", "COREN", "CRP",
}

PLANOS_SAUDE = {
    "amil", "unimed", "bradesco saúde", "bradesco saude",
    "sulamerica", "sul america", "hapvida", "notredame",
    "intermédica", "intermedica", "prevent senior", "porto seguro",
    "golden cross", "mediservice", "geap", "cassi",
    "saúde caixa", "saude caixa", "santa casa",
}

# ──────────────────────────────────────────────────────────────
# ESTADO GLOBAL
# ──────────────────────────────────────────────────────────────

session:       ort.InferenceSession = None
tokenizer:     AutoTokenizer        = None
cache:         OrderedDict          = OrderedDict()
cpu_high_count = 0

import platform
if platform.system() == "Windows":
    _sem      = asyncio.Semaphore(4)
    _executor = ThreadPoolExecutor(max_workers=4)
else:
    _sem      = asyncio.Semaphore(2)
    _executor = ThreadPoolExecutor(max_workers=1)

# ──────────────────────────────────────────────────────────────
# CACHE
# ──────────────────────────────────────────────────────────────

def cache_key(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()

def cache_get(texto: str):
    key = cache_key(texto)
    if key in cache:
        cache.move_to_end(key)
        return cache[key]
    return None

def cache_set(texto: str, valor):
    key = cache_key(texto)
    cache[key] = valor
    cache.move_to_end(key)
    while len(cache) > CACHE_SIZE:
        cache.popitem(last=False)

# ──────────────────────────────────────────────────────────────
# CHUNKING
# ──────────────────────────────────────────────────────────────

OVERLAP_CHARS = 150

def dividir_em_chunks(texto: str, max_chars: int = MAX_CHUNK_CHARS) -> list[str]:
    if len(texto) <= max_chars:
        return [texto]

    sentencas = re.split(r"(?<=[.!?\n])\s+", texto)
    raw_chunks, atual = [], ""

    for s in sentencas:
        if len(atual) + len(s) + 1 <= max_chars:
            atual = (atual + " " + s).strip()
        else:
            if atual:
                raw_chunks.append(atual)
            if len(s) > max_chars:
                palavras = s.split()
                sub = ""
                for p in palavras:
                    if len(sub) + len(p) + 1 <= max_chars:
                        sub = (sub + " " + p).strip()
                    else:
                        if sub:
                            raw_chunks.append(sub)
                        sub = p
                if sub:
                    raw_chunks.append(sub)
                atual = ""
            else:
                atual = s

    if atual:
        raw_chunks.append(atual)

    if len(raw_chunks) <= 1:
        return raw_chunks

    overlapped = [raw_chunks[0]]
    for i in range(1, len(raw_chunks)):
        tail = raw_chunks[i - 1][-OVERLAP_CHARS:]
        overlapped.append(tail + " " + raw_chunks[i])

    return overlapped

# ──────────────────────────────────────────────────────────────
# PRÉ-PROCESSAMENTO JSON & CAPITALIZAÇÃO
# ──────────────────────────────────────────────────────────────

def preparar_texto(texto: str) -> tuple[str, bool]:
    # Truque de Engenharia: Se o texto for 100% minúsculo, aplicamos Title Case
    # para simular maiúsculas iniciais e ajudar o modelo BERT cased a achar nomes.
    if texto.islower():
        texto = texto.title()
        logger.info("Texto 100% lowercase detectado. Aplicando Capitalização Virtual.")

    try:
        obj = json.loads(texto)
        pares = []

        def coletar(v, chave_pai=""):
            if isinstance(v, str) and v.strip():
                if chave_pai:
                    pares.append(f"{chave_pai}: {v.strip()}")
                else:
                    pares.append(v.strip())
            elif isinstance(v, dict):
                for k, val in v.items():
                    coletar(val, chave_pai=k)
            elif isinstance(v, list):
                for item in v:
                    coletar(item, chave_pai=chave_pai)

        coletar(obj)
        texto_limpo = " | ".join(pares)
        logger.info(f"JSON detectado — {len(pares)} pares extraídos")
        return texto_limpo, True
    except Exception:
        return texto, False

# ──────────────────────────────────────────────────────────────
# INFERÊNCIA — BERTimbau-leNER ONNX
# ──────────────────────────────────────────────────────────────

def _inferir_chunk(texto_chunk: str) -> list[dict]:
    global session, tokenizer

    encoded = tokenizer(
        texto_chunk,
        return_tensors="np",
        truncation=True,
        max_length=512,
        padding="max_length",
    )

    inputs_model = {i.name for i in session.get_inputs()}

    inputs = {
        "input_ids":      encoded["input_ids"].astype(np.int64),
        "attention_mask": encoded["attention_mask"].astype(np.int64),
    }
    if "token_type_ids" in inputs_model:
        inputs["token_type_ids"] = encoded.get(
            "token_type_ids", np.zeros_like(encoded["input_ids"])
        ).astype(np.int64)

    outputs  = session.run(None, inputs)
    logits   = outputs[0][0]
    pred_ids = np.argmax(logits, axis=-1)

    id2label  = _ID2LABEL
    tokens    = tokenizer.convert_ids_to_tokens(encoded["input_ids"][0])
    entidades = []
    atual_label, atual_tokens = None, []

    for token, pred_id in zip(tokens, pred_ids):
        if token in ("[CLS]", "[SEP]", "[PAD]"):
            if atual_label and atual_tokens:
                entidades.append({"label": atual_label, "valor": _reconstituir(atual_tokens)})
            atual_label, atual_tokens = None, []
            continue

        label_raw = id2label.get(int(pred_id), "O") if id2label else "O"

        if token.startswith("##"):
            if atual_label and atual_tokens:
                atual_tokens.append(token)
        elif label_raw.startswith("B-"):
            if atual_label and atual_tokens:
                entidades.append({"label": atual_label, "valor": _reconstituir(atual_tokens)})
            atual_label  = label_raw[2:]
            atual_tokens = [token]
        elif label_raw.startswith("I-") and atual_label == label_raw[2:]:
            if atual_tokens:
                atual_tokens.append(token)
        else:
            if atual_label and atual_tokens:
                entidades.append({"label": atual_label, "valor": _reconstituir(atual_tokens)})
            atual_label, atual_tokens = None, []

    if atual_label and atual_tokens:
        entidades.append({"label": atual_label, "valor": _reconstituir(atual_tokens)})

    return entidades

def _reconstituir(tokens: list[str]) -> str:
    texto = ""
    for t in tokens:
        if t.startswith("##"):
            texto += t[2:]
        elif t in (".", ",", "!", "?", ":", ";", ")", "]"):
            texto = texto.rstrip() + t
        else:
            texto = (texto + " " + t).strip()
    return texto.strip(",. ")

# ──────────────────────────────────────────────────────────────
# FILTROS PÓS-INFERÊNCIA
# ──────────────────────────────────────────────────────────────

ARTIGOS = {"da", "de", "do", "das", "dos", "e"}

def filtrar_entidades(entidades_raw: list[dict]) -> list[dict]:
    resultado, vistos = [], set()
    for ent in entidades_raw:
        label = ent.get("label", "").upper()
        valor = ent.get("valor", "").strip()
        if not label or not valor:
            continue
        tipo = LABEL_MAP.get(label) or LABEL_MAP.get(label.capitalize())
        if not tipo or tipo in TIPOS_BLOQUEADOS:
            continue
        if len(valor) < 3:
            continue
        if valor.lower() in VALORES_IGNORADOS:
            continue
        if tipo == "EMPRESA":
            if valor.upper() in SIGLAS_DOCUMENTOS:
                continue
            if valor.lower() in PLANOS_SAUDE:
                continue
            if len(valor.strip().split()) < 2:
                continue
        if tipo == "DATA_NASCIMENTO":
            if not re.search(r"\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}", valor):
                continue
            if not re.search(r"\d{2,4}$", valor):
                continue

        if tipo == "NOME_PESSOA":
            valor = valor.strip()
            if re.search(r"\d", valor):
                continue
            if ":" in valor:
                valor = valor.split(":")[-1].strip()
            partes = valor.split()
            if len(partes) < 2 or len(partes) > 5:
                continue
            ent["valor"] = valor

        chave = (tipo, valor.lower())
        if chave in vistos:
            continue
        vistos.add(chave)
        resultado.append({"tipo": tipo, "valor": valor})
    return resultado

def enriquecer_por_vinculo(entidades: list[dict], texto: str) -> list[dict]:
    PREFIXO = re.compile(
        r"(Dr\.?a?|Dra?\.?|Enf\.?|Fisio\.?|Psic\.?|Nutri\.?|Farm\.?)"
        r"\s+([A-ZÀÁÉÍÓÚ][a-záàâãéêíóôõúç]+(?:\s+[A-ZÀÁÉÍÓÚ][a-záàâãéêíóôõúç]+){1,3})"
    )
    REGISTRO = re.compile(
        r"\b(CRM|COREN|CRP|CRO|CRF)[\s\/\-]?(?:[A-Z]{2}[\s\/\-]?)?\d{4,7}\b"
    )

    nomes_detectados = {
        e["valor"].lower() for e in entidades
        if e["tipo"] in ("NOME_PESSOA", "PROFISSIONAL_SAUDE")
    }

    novos = []
    for m_reg in REGISTRO.finditer(texto):
        inicio = max(0, m_reg.start() - 100)
        contexto = texto[inicio:m_reg.start()]
        m_nome = PREFIXO.search(contexto)
        if m_nome:
            nome = m_nome.group(2).strip()
            if nome.lower() not in nomes_detectados and len(nome.split()) >= 2:
                novos.append({"tipo": "PROFISSIONAL_SAUDE", "valor": nome})
                nomes_detectados.add(nome.lower())
                logger.debug(f"Vínculo detectado: {nome} via {m_reg.group()}")

    return entidades + novos

# ──────────────────────────────────────────────────────────────
# CIRCUIT BREAKER
# ──────────────────────────────────────────────────────────────

def cpu_em_limite() -> bool:
    import platform
    if platform.system() == "Windows":
        return False
    global cpu_high_count
    cpu = psutil.cpu_percent(interval=0.1)
    if cpu >= CPU_LIMIT:
        cpu_high_count += 1
        logger.warning(f"CPU alta: {cpu:.1f}% (count={cpu_high_count})")
        return cpu_high_count >= 3
    else:
        cpu_high_count = max(0, cpu_high_count - 1)
        return False

# ──────────────────────────────────────────────────────────────
# LIFESPAN & WARMUP
# ──────────────────────────────────────────────────────────────

TEXTOS_WARMUP = [
    "Paciente Maria da Silva, CPF 123.456.789-09",
    "Dr. João Pereira, CRM SP 12345, atendeu na clínica",
    "Encaminhado para Rua das Flores, 42, São Paulo",
    "Responsável: Ana Costa, telefone (11) 98765-4321",
    "Prontuário 00123, nascido em 15/03/1985",
]

@asynccontextmanager
async def lifespan(app):
    global session, tokenizer

    logger.info(f"Carregando tokenizer: {MODEL_HF_ID}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_HF_ID)

    logger.info(f"Carregando modelo ONNX: {MODEL_ONNX}")
    opts = ort.SessionOptions()
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    if platform.system() == "Windows":
        opts.intra_op_num_threads = 0
        opts.inter_op_num_threads = 0
    else:
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1
    opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL

    session = ort.InferenceSession(
        MODEL_ONNX,
        sess_options=opts,
        providers=["CPUExecutionProvider"]
    )
    session.disable_fallback()

    logger.info("Modelo ONNX carregado. Iniciando warmup...")
    for texto in TEXTOS_WARMUP:
        try:
            _inferir_chunk(texto)
        except Exception as e:
            logger.warning(f"Warmup falhou em um texto: {e}")
    logger.info("Warmup concluído. Servidor pronto.")

    yield
    session   = None
    tokenizer = None
    logger.info("Modelo descarregado")

app = FastAPI(title="MascaraAI NER Server v3", lifespan=lifespan)

# ──────────────────────────────────────────────────────────────
# ROTAS
# ──────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "status": "ok",
        "model":  MODEL_HF_ID,
        "engine": "onnx-int8",
        "cache_entries": len(cache),
    }

@app.get("/health")
async def health():
    return {"ok": session is not None}

@app.get("/metrics")
async def metrics():
    return {
        "cache_entries":   len(cache),
        "cpu_percent":     psutil.cpu_percent(interval=0.1),
        "memory_mb":       psutil.virtual_memory().used // (1024 * 1024),
        "cpu_high_count":  cpu_high_count,
        "circuit_breaker": cpu_em_limite(),
    }

@app.post("/detect")
async def detect(request: Request):
    if session is None:
        raise HTTPException(503, "Modelo ainda carregando")

    if cpu_em_limite():
        logger.warning("Circuit breaker ativo — retornando lista vazia")
        return {"encontrados": [], "fallback": True}

    body  = await request.json()
    texto = str(body.get("text", ""))

    if not texto.strip():
        return {"encontrados": []}

    if len(texto) > MAX_CHARS:
        logger.info(f"Texto truncado: {len(texto)} → {MAX_CHARS} chars")
        texto = texto[:MAX_CHARS]

    cached = cache_get(texto)
    if cached is not None:
        logger.info(f"Cache hit — {len(cached)} entidades")
        return {"encontrados": cached}

    texto_modelo, e_json = preparar_texto(texto)
    chunks = dividir_em_chunks(texto_modelo)

    async with _sem:
        loop = asyncio.get_running_loop()
        t0   = time.monotonic()

        entidades_raw = []
        for chunk in chunks:
            result = await loop.run_in_executor(
                _executor,
                lambda c=chunk: _inferir_chunk(c)
            )
            entidades_raw.extend(result)

        tempo_ms = int((time.monotonic() - t0) * 1000)

    # Restaura a caixa original (lowercase) se o texto original do cliente era 100% minúsculo,
    # para que o Worker encontre e substitua os valores no texto dele.
    if texto.islower():
        for ent in entidades_raw:
            ent["valor"] = ent["valor"].lower()

    resultado = filtrar_entidades(entidades_raw)
    resultado = enriquecer_por_vinculo(resultado, texto_modelo)
    cache_set(texto, resultado)

    logger.info(
        f"Detectadas {len(resultado)} entidades "
        f"({len(entidades_raw)} brutas, {len(chunks)} chunks, {tempo_ms}ms)"
        f"{' — JSON' if e_json else ''}"
    )

    return {"encontrados": resultado}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "ner_server:app",
        host="0.0.0.0",
        port=8080,
        workers=1,
        log_level="info",
    )
