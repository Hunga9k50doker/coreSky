const fs = require("fs");
const path = require("path");
const axios = require("axios");
const colors = require("colors");
const { HttpsProxyAgent } = require("https-proxy-agent");
const readline = require("readline");
const user_agents = require("./config/userAgents");
const settings = require("./config/config.js");
const { sleep, loadData, getRandomNumber, saveToken, isTokenExpired, saveJson } = require("./utils.js");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const { checkBaseUrl } = require("./checkAPI");
const { headers } = require("./core/header.js");
const { showBanner } = require("./core/banner.js");
const localStorage = require("./localStorage.json");
const { Wallet, ethers } = require("ethers");
const { jwtDecode } = require("jwt-decode");

class ClientAPI {
  constructor(itemData, accountIndex, proxy, baseURL, authInfos) {
    this.headers = headers;
    this.baseURL = baseURL;
    this.baseURL_v2 = "";

    this.itemData = itemData;
    this.accountIndex = accountIndex;
    this.proxy = proxy;
    this.proxyIP = null;
    this.session_name = null;
    this.session_user_agents = this.#load_session_data();
    this.token = null;
    this.authInfos = authInfos;
    this.authInfo = null;
    this.localStorage = localStorage;
    this.wallet = new ethers.Wallet(this.itemData.privateKey);
  }

  #load_session_data() {
    try {
      const filePath = path.join(process.cwd(), "session_user_agents.json");
      const data = fs.readFileSync(filePath, "utf8");
      return JSON.parse(data);
    } catch (error) {
      if (error.code === "ENOENT") {
        return {};
      } else {
        throw error;
      }
    }
  }

  #get_random_user_agent() {
    const randomIndex = Math.floor(Math.random() * user_agents.length);
    return user_agents[randomIndex];
  }

  #get_user_agent() {
    if (this.session_user_agents[this.session_name]) {
      return this.session_user_agents[this.session_name];
    }

    console.log(`[Tài khoản ${this.accountIndex + 1}] Tạo user agent...`.blue);
    const newUserAgent = this.#get_random_user_agent();
    this.session_user_agents[this.session_name] = newUserAgent;
    this.#save_session_data(this.session_user_agents);
    return newUserAgent;
  }

  #save_session_data(session_user_agents) {
    const filePath = path.join(process.cwd(), "session_user_agents.json");
    fs.writeFileSync(filePath, JSON.stringify(session_user_agents, null, 2));
  }

  #get_platform(userAgent) {
    const platformPatterns = [
      { pattern: /iPhone/i, platform: "ios" },
      { pattern: /Android/i, platform: "android" },
      { pattern: /iPad/i, platform: "ios" },
    ];

    for (const { pattern, platform } of platformPatterns) {
      if (pattern.test(userAgent)) {
        return platform;
      }
    }

    return "Unknown";
  }

  #set_headers() {
    const platform = this.#get_platform(this.#get_user_agent());
    this.headers["sec-ch-ua"] = `Not)A;Brand";v="99", "${platform} WebView";v="127", "Chromium";v="127`;
    this.headers["sec-ch-ua-platform"] = platform;
    this.headers["User-Agent"] = this.#get_user_agent();
  }

  createUserAgent() {
    try {
      this.session_name = this.itemData.address;
      this.#get_user_agent();
    } catch (error) {
      this.log(`Can't create user agent: ${error.message}`, "error");
      return;
    }
  }

  async log(msg, type = "info") {
    const accountPrefix = `[CoreSky][Account ${this.accountIndex + 1}][${this.itemData.address}]`;
    let ipPrefix = "[Local IP]";
    if (settings.USE_PROXY) {
      ipPrefix = this.proxyIP ? `[${this.proxyIP}]` : "[Unknown IP]";
    }
    let logMessage = "";

    switch (type) {
      case "success":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.green;
        break;
      case "error":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.red;
        break;
      case "warning":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.yellow;
        break;
      case "custom":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.magenta;
        break;
      default:
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.blue;
    }
    console.log(logMessage);
  }

  async checkProxyIP() {
    try {
      const proxyAgent = new HttpsProxyAgent(this.proxy);
      const response = await axios.get("https://api.ipify.org?format=json", { httpsAgent: proxyAgent });
      if (response.status === 200) {
        this.proxyIP = response.data.ip;
        return response.data.ip;
      } else {
        throw new Error(`Cannot check proxy IP. Status code: ${response.status}`);
      }
    } catch (error) {
      throw new Error(`Error checking proxy IP: ${error.message}`);
    }
  }

  async makeRequest(
    url,
    method,
    data = {},
    options = {
      retries: 1,
      isAuth: false,
    }
  ) {
    const { retries, isAuth } = options;

    const headers = {
      ...this.headers,
      cookie: `refCode=${settings.REF_CODE}`,
    };

    if (!isAuth) {
      headers["Token"] = `${this.token}`;
    }

    let proxyAgent = null;
    if (settings.USE_PROXY) {
      proxyAgent = new HttpsProxyAgent(this.proxy);
    }
    let currRetries = 0;
    do {
      try {
        const response = await axios({
          method,
          url: `${url}`,
          headers,
          timeout: 60000,
          ...(proxyAgent ? { httpsAgent: proxyAgent } : {}),
          ...(method.toLowerCase() != "get" ? { data: JSON.stringify(data || {}) } : {}),
        });
        if (response?.data?.debug) return { status: response.status, success: true, data: response.data.debug };
        // else if (response?.data?.data) return { status: response.status, success: true, data: response.data.data };
        return { success: true, data: response.data, status: response.status };
      } catch (error) {
        const errorMessage = error?.response?.data?.error || error?.response?.data?.message || error.message;
        this.log(`Request failed: ${url} | ${error.message}...`, "warning");

        if (error.status == 401) {
          this.log(`Error 401: ${JSON.stringify(error.response.data)}`, "warning");
          let token = null;
          token = await this.getValidToken(true);
          if (!token) {
            process.exit(1);
          }
          this.token = token;
          return this.makeRequest(url, method, data, options);
        }
        if (error.status == 400) {
          this.log(`Invalid request for ${url}, maybe have new update from server | contact: https://t.me/airdrophuntersieutoc to get new update!`, "error");
          return { success: false, status: error.status, error: errorMessage };
        }
        if (error.status == 429) {
          this.log(`Rate limit ${error.message}, waiting 30s to retries`, "warning");
          await sleep(60);
        }
        await sleep(settings.DELAY_BETWEEN_REQUESTS);
        currRetries++;
        if (currRetries > retries) {
          // if (error.status == 500 && currRetries == retries + 1) {
          //   let token = null;
          //   token = await this.getValidToken(true);
          //   if (!token) {
          //     process.exit(1);
          //   }
          //   this.token = token;
          //   return this.makeRequest(url, method, data, options);
          // }
          return { status: error.status, success: false, error: errorMessage };
        }
      }
    } while (currRetries <= retries);
  }

  async auth() {
    const wallet = this.wallet;
    const loginMessage = `Welcome to CoreSky!\n\nClick to sign in and accept the CoreSky Terms of Service.\n\nThis request will not trigger a blockchain transaction or cost any gas fees.\n\nYour authentication status will reset after 24 hours.\n\nWallet address:\n\n${this.wallet.address}`;

    const signedMessage = await wallet.signMessage(loginMessage);
    const payload = { signature: signedMessage, projectId: "0", address: this.itemData.address, refCode: settings.REF_CODE };
    return this.makeRequest(`${this.baseURL}/user/login`, "post", payload, { isAuth: true });
  }

  async getUserData() {
    return this.makeRequest(`${this.baseURL}/user/token`, "post", {});
  }

  // async getBalance() {
  //   return this.makeRequest(`${this.baseURL}/user/token`, "post", {});
  // }

  async getTasks() {
    return this.makeRequest(`${this.baseURL}/taskwall/meme/tasks`, "get");
  }

  async checkin() {
    return this.makeRequest(`${this.baseURL}/taskwall/meme/sign`, "post");
  }

  async mint(payload) {
    //     {
    //     "responseToken": "03AFcWeA4GRL7dznIsGOWIm3gZW7k-xSJY23qd7ytsmAlsnwWqjnEDtbIzf9esItO0StzDeoQvSUewr9do5yIUagAWYP-C2xCj-rTHRZN_9-l9QiQB_TUc20Gnx2uY65u-zMQuidQSeOQHoXrSk6gMKvLrjOWeIZPGcwtCiA-V1WOMGEmPnKtKPMTMgCOWj6tzNz64tYSBBMW3SyQmzAuo_K9j5buWtoI2a2G35dexFWOtrKnq4WRErd7l6z28ZfWUc1CO165sCO1CU-19hvL4szzn-U69LtzIGMie3dFRQ2-V-ZBtd7QPihqMyRyHV-a7rC4z1cgRwXpE-GhxjL0biAc1XGz-szX2X1qBGRbgTET1TOKBjsr2bnJv4vYZDI_cZlG7ACiJ5Qj8CARWUjkmTQEIuyKU5W1_855AOxJoXUBJ15rbPKIao_OdZDhPe0GA3m_b_3qw-sc3SUQw0jx3HC5tF41AosY2f5HcGYLJBDBhLZOXQY1NHNuPaH6A-myDe1__urgv6PIkPNyditMUfRpe3athvrl0BH7lBMaVW1iMtbXFV-mLKVH_Ci29HmWFRkk-3KUTU-fpAfVFOexRd4P5G6kTEF88ndMdKAh19Akq4KkMrPXgJ-xp2T37R1z7puYjsmVdd8zj22T8vp0GsCStGSnu8g-SB9HQTLGEA5F-e2c5gu0irPCAo9CuJ8wnSLgScwV3459octpdhSY6rKiw1xjSaCZOiI0vpPAfotEdJDg3hdRMzlogPMjTztJUmejf4ystXlTV6dICseZ-S9s05f2ZEcNGQ29LpTxSYZPfao30xLJOvzmO8xpxdW5zilGsKLbQRnZU0H7-AhNlKcyLs1-ZcKq8Pcv45F7M6B9h5n7hR27gKLF-Kwd4BqVo9tcerW9HahMF35rya5oLa41zOzB-zkujbERIi4aVTU7AwIowbC1PmGDodxvqBXSvZ7aNVDYCa8xKpEsJ27NTGOpZZ4sk-gh4KKM6iBsWwz015bw1cugQNnMZ_-V4m2JkuUg-oKWfSKiJLGlH8n72PG1Zs1SNqforHOy7lXe-PxbDWZEFev100jlDxULyZ5Tj33KlPUCESCJH5bZ8DDgh7E_7KxnSNAycBDx5zT-HbzxuKqrMiYoS53CigCbpGJ22isw9Y5iNwQ9MI_XCiZUQM5xgyva8czk2pEsoVtn8EIW8MTzxIQ0BDSicIGHMitO451aM37AC2Lrgro7x9jpkEBeHHa5seTxAXFQR_jDt4mzX5JKIU9agUYR3E32TiMzIqLDivw57Pu8lGyiQd7KYqCDpnTgTotWszEQeaOC18845Wg6n1dwOGSsOQImQsDKFYsQ7yNWT36sV8J-4YSZ0tjH2rrO21MjAyaGcR6VTGT02TVcyziE6S-e9fzr1Ze77t3IUKm0n-5fglsoZ7kGGeHVi7V0Iw_NcyUsax09NP0YNhooVL9yrV-4c-Q7hZeXuvTNatpr6K-NepkNOuocF5Y5ziXdkhKcVaWsZfwaHI4QC62bqcL7hBcVY7gCp3HZMrOixcjMpHTiEOCze6LuXMxTWr1ubcGqVmZjys1UjwTByPweEpdJ2YMr8WeIOo6i0oUgFP6-9z491_0GJlah2A7WaoT7VyCF0wNhx9Wr4zq8BSuzSIokmV5IdCLB4f2UjYasWfFa_5olzOciRgj5uvdCttxCxU4YE_WxRRuftRbP3YEkNSYRLTyNw2UG5sbK6wINS2aJ82wQYz2JiRjSjQYnRT9lw4iST9WNcCJhYJbMYEnwohLiq-tIkme-uvrcPI41TTe7iRFlHM4_DU0TY_LuXdvWpqXX_lfDkqPjyZ1UUS8kyLh-YPLLXddw_S5AyvW8vwpcht9h-LW-siNHmKl2yhi_o1lSOZ0jGGBrC9Yaht9wMQJndRjb2OgnTonDWr-I4ppdOT7F-b0nXWn9OrmdsJSH835aoLuxQEZHwhy15gQ58FJTEncMnMAwQBT5udH7s_HfivAZD1V16YQHn-bbW70YiQ409GFDkUvYWpp1K6nuRe1C75lwWC-fAFHJiEhigJbelRQS47-cxhjYmejX0LlPNW-fI7-pxZ9fOYBjJhXzM5c2nEf0Dd7NxmtoUc8dy9r-dbJ6G"
    // }
    return this.makeRequest(`${this.baseURL}/luckdraw/mint`, "post", payload);
  }

  async spin(payload) {
    // "sign": "0xa746b9f05e6170207a36f053ec4dbf02f465714911cd91804a93eda1bc4ce73e58a3062f49952469616ed5094712bd8d8dbf6c16b42c240212369e82f28b67561c",
    //       "serialNo": "1904843245123039232",
    //       "deadline": "1742985294572",
    //       "amount": "1",
    //       "tokenId": "50640"
    return this.makeRequest(`${this.baseURL}/luckdraw/open`, "post", {
      useSbt: true,
    });
  }

  async checkMint() {
    // "nextMintTime": "48708000",
    //     "minted": 1
    return this.makeRequest(`${this.baseURL}/luckdraw/mint`, "get");
  }

  async completeTask(payload) {
    return this.makeRequest(`${this.baseURL}/taskwall/meme/sign`, "post", payload);
  }

  async getValidToken(isNew = false) {
    const existingToken = this.token;
    const { isExpired: isExp, expirationDate } = isTokenExpired(existingToken);

    this.log(`Access token status: ${isExp ? "Expired".yellow : "Valid".green} | Acess token exp: ${expirationDate}`);
    if (existingToken && !isNew && !isExp) {
      this.log("Using valid token", "success");
      return existingToken;
    }

    this.log("No found token or experied, trying get new token...", "warning");
    const loginRes = await this.auth();
    if (!loginRes?.success) return null;
    const newData = loginRes.data;
    if (newData?.token) {
      saveJson(this.session_name, JSON.stringify(newData), "tokens.json");
      return newData.token;
    }
    this.log("Can't get new token...", "warning");
    return null;
  }

  async handleSyncData() {
    let userData = { success: true, data: null, status: 0 },
      retries = 0;

    do {
      userData = await this.getUserData();
      if (userData?.success) break;
      retries++;
    } while (retries < 1 && userData.status !== 400);

    if (userData.success) {
      const { userVerify, email, nickname, refCode, score } = userData.data;
      this.log(`Name: ${nickname || "Unknow"} | Ref code: ${refCode || "Not verify"} | Verified: ${userVerify || "false"} | Points: ${score || 0}`, "custom");
    } else {
      return this.log("Can't sync new data...skipping", "warning");
    }
    return userData;
  }

  async handleTask() {
    let tasks = [];
    const result = await this.getTasks();
    if (!result.success) return;
    const tasksAvailable = result.data.filter((task) => task.taskStatus !== 2 && task.id == 1 && !settings.SKIP_TASKS.includes(task.id));
    tasks = [...tasks, ...tasksAvailable];

    if (tasks.length == 0) return this.log(`No tasks available!`, "warning");
    for (const task of tasks) {
      this.log(`Trying complete task: ${task.id} | ${task.taskName}...`, "info");
      if (task.id == 1) {
        const resCheckin = await this.checkin();
        if (resCheckin.success) this.log(`Checkin success | Reward: ${task.rewardPoint}`, "success");
        else this.log(`Can't checkin | ${JSON.stringify(resCheckin)}`, "warning");
      }
      // else {
      //   const resClaim = await this.completeTask({
      //     uuid: task.uuid,
      //   });
      //   if (resClaim.success && resClaim.data.isCompleted) this.log(`Claim task ${task.id} | ${task.taskName} success | Reward: ${task.rewardPoint}`, "success");
      //   else this.log(`Can't claim task ${task.id} | ${task.taskName} | ${JSON.stringify(resClaim)}`, "warning");
      // }
      // await sleep(1);
    }
  }

  async runAccount() {
    const accountIndex = this.accountIndex;
    this.session_name = this.itemData.address;
    this.authInfo = JSON.parse(this.authInfos[this.session_name] || "{}");
    this.token = this.authInfo?.token;
    this.#set_headers();
    if (settings.USE_PROXY) {
      try {
        this.proxyIP = await this.checkProxyIP();
      } catch (error) {
        this.log(`Cannot check proxy IP: ${error.message}`, "warning");
        return;
      }
      const timesleep = getRandomNumber(settings.DELAY_START_BOT[0], settings.DELAY_START_BOT[1]);
      console.log(`=========Tài khoản ${accountIndex + 1} | ${this.proxyIP} | Bắt đầu sau ${timesleep} giây...`.green);
      await sleep(timesleep);
    }

    const token = await this.getValidToken();
    if (!token) return;
    this.token = token;
    const userData = await this.handleSyncData();
    if (userData.success) {
      await this.handleTask();
      await sleep(1);
      // await this.handleSyncData();
    } else {
      return this.log("Can't get use info...skipping", "error");
    }
  }
}

async function runWorker(workerData) {
  const { itemData, accountIndex, proxy, hasIDAPI, authInfos } = workerData;
  const to = new ClientAPI(itemData, accountIndex, proxy, hasIDAPI, authInfos);
  try {
    await Promise.race([to.runAccount(), new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 24 * 60 * 60 * 1000))]);
    parentPort.postMessage({
      accountIndex,
    });
  } catch (error) {
    parentPort.postMessage({ accountIndex, error: error.message });
  } finally {
    if (!isMainThread) {
      parentPort.postMessage("taskComplete");
    }
  }
}

async function main() {
  showBanner();

  fs.writeFileSync("tokens.json", "{}", (err) => {
    if (err) {
      console.error("Error clearing the file:", err);
    } else {
      console.log("File cleared successfully.");
    }
  });
  await sleep(2);
  const privateKeys = loadData("privateKeys.txt");
  const proxies = loadData("proxy.txt");
  let authInfos = require("./tokens.json");

  if (privateKeys.length == 0 || (privateKeys.length > proxies.length && settings.USE_PROXY)) {
    console.log("Số lượng proxy và data phải bằng nhau.".red);
    console.log(`Data: ${privateKeys.length}`);
    console.log(`Proxy: ${proxies.length}`);
    process.exit(1);
  }
  if (!settings.USE_PROXY) {
    console.log(`You are running bot without proxies!!!`.yellow);
  }
  let maxThreads = settings.USE_PROXY ? settings.MAX_THEADS : settings.MAX_THEADS_NO_PROXY;

  const { endpoint, message } = await checkBaseUrl();
  if (!endpoint) return console.log(`Không thể tìm thấy ID API, thử lại sau!`.red);
  console.log(`${message}`.yellow);

  const data = privateKeys.map((val, index) => {
    const prvk = val.startsWith("0x") ? val : `0x${val}`;
    const wallet = new ethers.Wallet(prvk);
    const item = {
      privateKey: prvk,
      address: wallet.address,
      wallet: wallet,
    };
    new ClientAPI(item, index, proxies[index], endpoint, {}).createUserAgent();
    return item;
  });
  await sleep(1);
  while (true) {
    authInfos = require("./tokens.json");
    let currentIndex = 0;
    const errors = [];
    while (currentIndex < data.length) {
      const workerPromises = [];
      const batchSize = Math.min(maxThreads, data.length - currentIndex);
      for (let i = 0; i < batchSize; i++) {
        const worker = new Worker(__filename, {
          workerData: {
            hasIDAPI: endpoint,
            itemData: data[currentIndex],
            accountIndex: currentIndex,
            proxy: proxies[currentIndex % proxies.length],
            authInfos: authInfos,
          },
        });

        workerPromises.push(
          new Promise((resolve) => {
            worker.on("message", (message) => {
              if (message === "taskComplete") {
                worker.terminate();
              }
              if (settings.ENABLE_DEBUG) {
                console.log(message);
              }
              resolve();
            });
            worker.on("error", (error) => {
              console.log(`Lỗi worker cho tài khoản ${currentIndex}: ${error?.message}`);
              worker.terminate();
              resolve();
            });
            worker.on("exit", (code) => {
              worker.terminate();
              if (code !== 0) {
                errors.push(`Worker cho tài khoản ${currentIndex} thoát với mã: ${code}`);
              }
              resolve();
            });
          })
        );

        currentIndex++;
      }

      await Promise.all(workerPromises);

      if (errors.length > 0) {
        errors.length = 0;
      }

      if (currentIndex < data.length) {
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }
    }

    await sleep(3);
    console.log(`=============${new Date().toLocaleString()} | Hoàn thành tất cả tài khoản | Chờ ${settings.TIME_SLEEP} phút=============`.magenta);
    showBanner();
    await sleep(settings.TIME_SLEEP * 60);
  }
}

if (isMainThread) {
  main().catch((error) => {
    console.log("Lỗi rồi:", error);
    process.exit(1);
  });
} else {
  runWorker(workerData);
}
