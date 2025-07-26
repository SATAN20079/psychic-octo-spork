import telegram
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, InlineQueryHandler
import aiohttp
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
import re
from datetime import datetime

# تنظیمات لاگ
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# توکن‌ها
BOT_TOKEN = "7988752445:AAHz2A4FS4rDuPUbqu2KRQLO-7m4xLb954g"
HF_API_TOKEN = "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"

# آدرس API هوش مصنوعی
HF_API_URL = "https://api-inference.huggingface.co/models/distilbert-base-uncased-finetuned-sst-2-english"

# لیست برای ذخیره نتایج
results = []
MAX_RESULTS = 100

# تابع برای ارتباط با Hugging Face API
async def query_hugging_face(text):
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
    async with aiohttp.ClientSession() as session:
        async with session.post(HF_API_URL, headers=headers, json={"inputs": text}) as response:
            if response.status == 200:
                return await response.json()
            else:
                logger.error(f"Error in Hugging Face API: {response.status}")
                return None

# تابع برای سرچ توی کانال‌های مشخص
async def search_channel(channel, keyword):
    search_results = []
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates?chat_id={channel}&q={keyword}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("ok") and data.get("result"):
                        for update in data["result"]:
                            if "message" in update and keyword.lower() in str(update["message"]).lower():
                                search_results.append({"content": update["message"].get("text", ""), "date": update["message"].get("date", 0)})
    except Exception as e:
        logger.error(f"Error searching {channel}: {e}")
    return search_results

# تابع برای استخراج لینک‌ها
def extract_links(text):
    url_pattern = re.compile(r'https?://\S+|www\.\S+')
    return url_pattern.findall(text)

# تابع برای کرال لینک‌ها با شبیه‌سازی ابزارهای هک
async def crawl_links(url):
    if len(results) >= MAX_RESULTS:
        return
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    links = extract_links(text)
                    for link in links[:5]:
                        if len(results) < MAX_RESULTS:
                            # شبیه‌سازی ابزارهای هک (Wireshark, Nmap, Metasploit)
                            content = await analyze_worm_traffic(link)
                            if content:
                                results.append({"url": link, "content": content, "source": "crawled"})
    except Exception as e:
        logger.error(f"Error crawling {url}: {e}")

# تابع برای تحلیل ترافیک کرم‌ها با AI
async def analyze_worm_traffic(url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    # شبیه‌سازی Wireshark: تحلیل ترافیک
                    traffic_analysis = "Traffic pattern detected: Possible worm replication."
                    # شبیه‌سازی Nmap: اسکن آسیب‌پذیری
                    vuln_scan = "Vulnerability found: Open port 445 (SMB)."
                    # شبیه‌سازی Metasploit: اکسپلویت
                    exploit_sim = "Exploit simulated: Worm payload detected."
                    analysis = await query_hugging_face(f"{text[:500]} {traffic_analysis} {vuln_scan} {exploit_sim}")
                    return f"Extracted: {text[:200]}... (Wireshark: {traffic_analysis}, Nmap: {vuln_scan}, Metasploit: {exploit_sim}, AI: {analysis})"
    except Exception:
        return None

# تابع اصلی برای سرچ و پردازش
async def process_search(keywords, channels, update, context):
    global results
    results = []
    keyword = " ".join(keywords[:20])  # ترکیب کلمات کلیدی
    if not keyword.lower().startswith("worm") and not any(kw in keyword.lower() for kw in ["exploit", "hack", "vulnerability"]):
        keyword += " worm exploit"  # اضافه کردن کلمات مرتبط با کرم

    # سرچ توی کانال‌های مشخص‌شده
    tasks = [search_channel(channel, keyword) for channel in channels]
    search_results = await asyncio.gather(*tasks)
    for channel_results in search_results:
        for result in sorted(channel_results, key=lambda x: x.get("date", 0), reverse=True)[:50]:  # جدیدترین 50 نتیجه
            if len(results) < MAX_RESULTS and "content" in result:
                results.append({"content": result["content"], "source": "telegram"})
                links = extract_links(result["content"])
                for link in links:
                    await crawl_links(link)

    # فیلتر کردن محتوای مرتبط با کرم
    worm_results = [r for r in results if any(kw in str(r).lower() for kw in ["worm", "exploit", "vulnerability", "payload"])]
    for result in worm_results[:MAX_RESULTS]:
        if "content" in result:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"منبع: {result['source']}\nمحتوا: {result.get('content', result.get('url', 'N/A'))}"
            )

# هندلرها
def start(update, context):
    update.message.reply_text("سلام! کلمات کلیدی بفرست (مثل 'worm exploit') یا از /kanalha برای تنظیم کانال‌ها استفاده کن.")

def handle_message(update, context):
    keywords = update.message.text.split()
    context.job_queue.run_once(lambda x: asyncio.run(process_search(keywords, ["@DarkForumsLeak", "@MoonCloudLogs"], update, context)), 0)

def set_channels(update, context):
    if context.args:
        channels = [chan for chan in context.args if chan.startswith("@")]
        if channels:
            context.job_queue.run_once(lambda x: asyncio.run(process_search(["worm exploit"], channels, update, context)), 0)  # پیش‌فرض کرم
            update.message.reply_text(f"کانال‌ها تنظیم شدند: {', '.join(channels)}. سرچ شروع شد.")
        else:
            update.message.reply_text("لطفاً حداقل یک کانال با @ وارد کن (مثل /kanalha @Channel1 @Channel2).")
    else:
        update.message.reply_text("لطفاً کانال‌ها رو با @ وارد کن (مثل /kanalha @Channel1 @Channel2).")

def error_handler(update, context):
    logger.error(f"Update {update} caused error {context.error}")

def main():
    updater = Updater(BOT_TOKEN, use_context=True)
    dp = updater.dispatcher
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))
    dp.add_handler(CommandHandler("kanalha", set_channels, pass_args=True))
    dp.add_error_handler(error_handler)
    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()