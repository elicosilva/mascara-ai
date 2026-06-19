import fs from "fs";

const logPath = "C:/Users/elic1/.gemini/antigravity/brain/96b248de-a2d0-4a86-9854-0c6cbddff8d6/.system_generated/logs/transcript.jsonl";

function run() {
  if (!fs.existsSync(logPath)) {
    console.error("Log file not found!");
    return;
  }
  const fileContent = fs.readFileSync(logPath, "utf8");
  const lines = fileContent.split("\n");
  
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const step = JSON.parse(line);
      if (step.step_index === 1) {
        console.log("Found step 1!");
        console.log("Keys in step 1:", Object.keys(step));
        if (step.content) {
          console.log("Content length:", step.content.length);
          fs.writeFileSync("step_1_content.txt", step.content, "utf8");
          console.log("Wrote step 1 content to step_1_content.txt");
        }
        if (step.tool_calls) {
          console.log("Tool calls:", step.tool_calls);
        }
      }
    } catch (e) {
      console.error(e);
    }
  }
}

run();
