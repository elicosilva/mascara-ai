import fs from "fs";

const rawPromptPath = "C:/Users/elic1/.gemini/antigravity/scratch/mascara-ai/initial_prompt_raw.txt";

function run() {
  if (!fs.existsSync(rawPromptPath)) {
    console.error("rawPromptPath file not found!");
    return;
  }
  const text = fs.readFileSync(rawPromptPath, "utf8");
  
  // Find /detect or GLINER_URL
  let index = text.indexOf("/detect");
  if (index === -1) index = text.indexOf("GLINER_URL");
  
  if (index !== -1) {
    console.log("--- FOUND /detect or GLINER_URL IN RAW PROMPT ---");
    console.log(text.substring(index - 500, index + 1500));
    console.log("--------------------------------------------------");
  } else {
    console.log("Not found in raw prompt");
  }
}

run();
