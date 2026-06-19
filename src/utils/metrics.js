// Utilitário para rastreamento de métricas e tempos de execução do pipeline
export class MetricsTracker {
  constructor() {
    this.startTimes = {};
    this.durations = {
      tempo_ms: 0,
      regex_ms: 0,
      ner_ms: 0
    };
  }

  start(key) {
    this.startTimes[key] = Date.now();
  }

  stop(key) {
    if (this.startTimes[key]) {
      const duration = Date.now() - this.startTimes[key];
      if (key === "total") {
        this.durations.tempo_ms = duration;
      } else if (key === "regex") {
        this.durations.regex_ms = duration;
      } else if (key === "ner") {
        this.durations.ner_ms = duration;
      }
    }
  }

  getResults() {
    return {
      tempo_ms: this.durations.tempo_ms,
      regex_ms: this.durations.regex_ms,
      ner_ms: this.durations.ner_ms
    };
  }
}
