import fs from "fs";

const logPath = "C:/Users/elic1/.gemini/antigravity/brain/96b248de-a2d0-4a86-9854-0c6cbddff8d6/.system_generated/logs/transcript.jsonl";

function run() {
  if (!fs.existsSync(logPath)) {
    console.error("Log file not found!");
    return;
  }
  const fileContent = fs.readFileSync(logPath, "utf8");
  const lines = fileContent.split("\n");
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes("encontrados")) {
      try {
        const step = JSON.parse(line);
        if (step.step_index < 75) {
          console.log(`Line ${i} (Step ${step.step_index}): contains encontrados.`);
          // Print context
          const text = step.content || "";
          const idx = text.indexOf("encontrados");
          console.log(text.substring(idx - 200, idx + 500));
        }
      } catch (e) {
        // ignore
      }
    }
  }
}

run();
