const config = require("./config/config");
const colors = require("colors");
const axios = require("axios");
const solve2Captcha = async () => {
  let retries = 5;
  try {
    // Step 1: Create a CAPTCHA task
    const taskResponse = await axios.post(
      "https://api.2captcha.com/createTask",
      {
        clientKey: config.API_KEY_2CAPTCHA,
        task: {
          type: "RecaptchaV2TaskProxyless",
          websiteURL: config.CAPTCHA_URL,
          websiteKey: config.WEBSITE_KEY,
        },
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );

    const requestId = taskResponse.data.taskId;
    if (!requestId) throw new Error(JSON.stringify(taskResponse.data));
    // Step 2: Poll for the result
    let result;
    do {
      await new Promise((resolve) => setTimeout(resolve, 10000));
      const resultResponse = await axios.post(
        "https://api.2captcha.com/getTaskResult",
        {
          clientKey: config.API_KEY_2CAPTCHA,
          taskId: requestId,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      result = resultResponse.data;
      if (result.status === "processing") {
        console.log(colors.yellow("CAPTCHA still processing..."));
      }
      retries--;
    } while (result.status === "processing" && retries > 0);

    // Step 3: Use the CAPTCHA solution
    if (result.status === "ready") {
      console.log(colors.green("CAPTCHA success.."));
      const captchaSolution = result.solution.token; // This is the CAPTCHA token

      // Use the token in your request
      return captchaSolution; // Store the token for further use

      // You can now send this token to the backend or use it as needed
    } else {
      console.error("Error:", result);
      return null;
    }
  } catch (error) {
    console.error("Error:", error.message);
    return null;
  }
};

const solveAntiCaptcha = async () => {
  let retries = 5;
  try {
    // Step 1: Create a CAPTCHA task
    const taskResponse = await axios.post(
      "https://api.anti-captcha.com/createTask",
      {
        clientKey: config.API_KEY_ANTI_CAPTCHA,
        task: {
          type: "RecaptchaV2TaskProxyless",
          websiteURL: config.CAPTCHA_URL,
          websiteKey: config.WEBSITE_KEY,
          isInvisible: false,
        },
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );

    const requestId = taskResponse.data.taskId;
    if (!requestId) {
      throw new Error("Failed to create CAPTCHA task. No task ID returned.");
    }

    // Step 2: Poll for the result
    let result;
    do {
      await new Promise((resolve) => setTimeout(resolve, 10000));
      const resultResponse = await axios.post(
        "https://api.anti-captcha.com/getTaskResult",
        {
          clientKey: config.API_KEY_ANTI_CAPTCHA,
          taskId: requestId,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      result = resultResponse.data;
      if (result.status === "processing") {
        console.log(colors.yellow("CAPTCHA still processing..."));
      }
      retries--;
    } while (result.status === "processing" && retries > 0);

    // Step 3: Use the CAPTCHA solution
    if (result.status === "ready") {
      console.log(colors.green("CAPTCHA success.."));
      const captchaSolution = result.solution.token; // This is the CAPTCHA token

      // Use the token in your request
      return captchaSolution; // Store the token for further use
    } else {
      console.error("Error:", result);
      return null;
    }
  } catch (error) {
    console.error("Error:", error.message);
    return null;
  }
};

async function sovleCaptcha() {
  if (config.TYPE_CAPTCHA === "2captcha") {
    return await solve2Captcha();
  } else if (config.TYPE_CAPTCHA === "anticaptcha") return await solveAntiCaptcha();
  console.log("Invalid type captcha".yellow);
  return null;
}

module.exports = { sovleCaptcha };
