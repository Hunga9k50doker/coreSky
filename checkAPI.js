const axios = require("axios");
const { log } = require("./utils"); // Adjust the path as necessary
const settings = require("./config/config");

const urlChecking = "https://raw.githubusercontent.com/Hunga9k50doker/APIs-checking/refs/heads/main/endpoints.json";

async function checkBaseUrl() {
  console.log("Checking api...".blue);
  if (settings.ADVANCED_ANTI_DETECTION) {
    const result = await getBaseApi(urlChecking);
    if (result.endpoint) {
      log("No change in api!", "success");
      return result;
    }
  } else {
    return {
      endpoint: settings.BASE_URL,
      message:
        "Nếu api thay đổi vui lòng liên hệ nhóm tele Airdrop Hunter Siêu Tốc (https://t.me/airdrophuntersieutoc) để biết thêm thông tin và cập nhật!| Have any issuess, please contact: https://t.me/airdrophuntersieutoc",
    };
  }
}

async function getBaseApi(url) {
  try {
    const response = await axios.get(url);
    const content = response.data;
    if (content?.ogLab) {
      return { endpoint: content.ogLab, message: content.copyright };
    } else {
      return {
        endpoint: null,
        message:
          "Nếu api thay đổi vui lòng liên hệ nhóm tele Airdrop Hunter Siêu Tốc (https://t.me/airdrophuntersieutoc) để biết thêm thông tin và cập nhật!| Have any issuess, please contact: https://t.me/airdrophuntersieutoc",
      };
    }
  } catch (e) {
    return {
      endpoint: null,
      message:
        "Nếu api thay đổi vui lòng liên hệ nhóm tele Airdrop Hunter Siêu Tốc (https://t.me/airdrophuntersieutoc) để biết thêm thông tin và cập nhật!| Have any issuess, please contact: https://t.me/airdrophuntersieutoc",
    };
  }
}

module.exports = { checkBaseUrl };
