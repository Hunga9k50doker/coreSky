const fs = require("fs");
const colors = require("colors");
const path = require("path");
require("dotenv").config();
const { jwtDecode } = require("jwt-decode");

function _isArray(obj) {
  if (Array.isArray(obj) && obj.length > 0) {
    return true;
  }

  try {
    const parsedObj = JSON.parse(obj);
    return Array.isArray(parsedObj) && parsedObj.length > 0;
  } catch (e) {
    return false;
  }
}

function parseQueryString(query) {
  const params = new URLSearchParams(query);
  const parsedQuery = {};

  for (const [key, value] of params) {
    parsedQuery[key] = decodeURIComponent(value);
  }

  return parsedQuery;
}

function splitIdPet(num) {
  const numStr = num.toString();
  const firstPart = numStr.slice(0, 3); // Lấy 3 ký tự đầu tiên
  const secondPart = numStr.slice(3); // Lấy phần còn lại

  return [parseInt(firstPart), parseInt(secondPart)];
}

// Hàm để ghi đè biến môi trường
const envFilePath = path.join(__dirname, ".env");
function updateEnv(variable, value) {
  // Đọc file .env
  fs.readFile(envFilePath, "utf8", (err, data) => {
    if (err) {
      console.log("Không thể đọc file .env:", err);
      return;
    }

    // Tạo hoặc cập nhật biến trong file
    const regex = new RegExp(`^${variable}=.*`, "m");
    let newData = data.replace(regex, `${variable}=${value}`); // Sử dụng let thay vì const

    // Kiểm tra nếu biến không tồn tại trong file, thêm vào cuối
    if (!regex.test(data)) {
      newData += `\n${variable}=${value}`;
    }

    // Ghi lại file .env
    fs.writeFile(envFilePath, newData, "utf8", (err) => {
      if (err) {
        console.error("Không thể ghi file .env:", err);
      } else {
        // console.log(`Đã cập nhật ${variable} thành ${value}`);
      }
    });
  });
}

function sleep(seconds = null) {
  if (seconds && typeof seconds === "number") return new Promise((resolve) => setTimeout(resolve, seconds * 1000));

  let DELAY_BETWEEN_REQUESTS = [1, 5];
  if (seconds && Array.isArray(seconds)) {
    DELAY_BETWEEN_REQUESTS = seconds;
  }
  min = DELAY_BETWEEN_REQUESTS[0];
  max = DELAY_BETWEEN_REQUESTS[1];

  return new Promise((resolve) => {
    const delay = Math.floor(Math.random() * (max - min + 1)) + min;
    setTimeout(resolve, delay * 1000);
  });
}

function randomDelay() {
  return new Promise((resolve) => {
    const minDelay = process.env.DELAY_REQUEST_API[0];
    const maxDelay = process.env.DELAY_REQUEST_API[1];
    const delay = Math.floor(Math.random() * (maxDelay - minDelay + 1)) + minDelay;
    setTimeout(resolve, delay * 1000);
  });
}

function saveToken(id, token) {
  const tokens = JSON.parse(fs.readFileSync("tokens.json", "utf8"));
  tokens[id] = token;
  fs.writeFileSync("tokens.json", JSON.stringify(tokens, null, 4));
}

function getToken(id) {
  const tokens = JSON.parse(fs.readFileSync("tokens.json", "utf8"));
  return tokens[id] || null;
}
function isTokenExpired(token) {
  if (!token) return { isExpired: true, expirationDate: new Date().toLocaleString() };

  try {
    const payload = jwtDecode(token);
    if (!payload) return true;

    const now = Math.floor(Date.now() / 1000);

    const expirationDate = new Date(payload.exp * 1000).toLocaleString();
    const isExpired = now > payload.exp;

    return { isExpired, expirationDate };
  } catch (error) {
    console.log(`Error checking token: ${error.message}`.red);
    return { isExpired: true, expirationDate: new Date().toLocaleString() };
  }
}

function generateRandomHash() {
  const characters = "0123456789abcdef";
  let hash = "0x"; // Bắt đầu bằng "0x"

  for (let i = 0; i < 64; i++) {
    // 64 ký tự cho hash
    const randomIndex = Math.floor(Math.random() * characters.length);
    hash += characters[randomIndex];
  }

  return hash;
}

function getRandomElement(arr) {
  const randomIndex = Math.floor(Math.random() * arr.length);
  return arr[randomIndex];
}

function getRandomNumber(min, max) {
  return Math.floor(Math.random() * (max - min) + min);
}

function loadData(file) {
  try {
    const datas = fs.readFileSync(file, "utf8").replace(/\r/g, "").split("\n").filter(Boolean);
    if (datas?.length <= 0) {
      console.log(colors.red(`Không tìm thấy dữ liệu ${file}`));
      return [];
    }
    return datas;
  } catch (error) {
    console.log(`Không tìm thấy file ${file}`.red);
    return [];
  }
}

async function saveData(data, filename) {
  fs.writeFileSync(filename, data.join("\n"));
}

function log(msg, type = "info") {
  switch (type) {
    case "success":
      console.log(`[*] ${msg}`.green);
      break;
    case "custom":
      console.log(`[*] ${msg}`.magenta);
      break;
    case "error":
      console.log(`[!] ${msg}`.red);
      break;
    case "warning":
      console.log(`[*] ${msg}`.yellow);
      break;
    default:
      console.log(`[*] ${msg}`.blue);
  }
}

function saveJson(id, value, filename) {
  const data = JSON.parse(fs.readFileSync(filename, "utf8"));
  data[id] = value;
  fs.writeFileSync(filename, JSON.stringify(data, null, 4));
}

function getItem(id, filename) {
  const data = JSON.parse(fs.readFileSync(filename, "utf8"));
  return data[id] || null;
}

function getOrCreateJSON(id, value, filename) {
  let item = getItem(id, filename);
  if (item) {
    return item;
  }
  item = saveJson(id, value, filename);
  return item;
}

function generateComplexId(length = 9) {
  const chars = "0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function getRandomNineDigitNumber() {
  const min = 100000000; // Số 9 chữ số nhỏ nhất
  const max = 999999999; // Số 9 chữ số lớn nhất
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function decodeJWT(token) {
  const [header, payload, signature] = token.split(".");

  // Decode Base64 URL
  const decodeBase64Url = (str) => {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(str));
  };

  const decodedHeader = decodeBase64Url(header);
  const decodedPayload = decodeBase64Url(payload);

  return {
    header: decodedHeader,
    payload: decodedPayload,
    signature: signature, // You might not need to decode the signature
  };
}

module.exports = {
  _isArray,
  saveJson,
  decodeJWT,
  generateComplexId,
  getRandomNumber,
  updateEnv,
  saveToken,
  splitIdPet,
  getToken,
  isTokenExpired,
  generateRandomHash,
  getRandomElement,
  loadData,
  saveData,
  log,
  getOrCreateJSON,
  sleep,
  randomDelay,
  parseQueryString,
  getRandomNineDigitNumber,
};
