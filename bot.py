import os
import dns.resolver
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

# ================= CONFIG =================
BOT_TOKEN = os.getenv("BOT_TOKEN")
THREADS = int(os.getenv("THREADS", "10"))
TIMEOUT = 5

# ================= FINGERPRINT =================
FINGERPRINTS = {
    "AWS S3": {
        "cnames": ["amazonaws.com"],
        "signatures": ["NoSuchBucket", "The specified bucket does not exist"]
    },
    "GitHub Pages": {
        "cnames": ["github.io"],
        "signatures": ["There isn't a GitHub Pages site here"]
    },
    "Heroku": {
        "cnames": ["herokuapp.com", "herokudns.com"],
        "signatures": ["no such app"]
    },
    "Vercel": {
        "cnames": ["vercel.app"],
        "signatures": ["404: This page could not be found"]
    },
    "Netlify": {
        "cnames": ["netlify.app"],
        "signatures": ["not found"]
    }
}

# ================= SCANNER =================
class Scanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.vuln_count = 0

    def get_cname(self, domain):
        try:
            answers = dns.resolver.resolve(domain, "CNAME")
            return str(answers[0].target).rstrip(".")
        except:
            return None

    def detect_service(self, cname):
        if not cname:
            return None
        for service, data in FINGERPRINTS.items():
            for pattern in data["cnames"]:
                if pattern in cname.lower():
                    return service
        return None

    def check_takeover(self, domain, service):
        try:
            r = requests.get(f"https://{domain}", timeout=TIMEOUT)
            for sig in FINGERPRINTS[service]["signatures"]:
                if sig.lower() in r.text.lower():
                    return True
        except:
            pass
        return False

    def scan(self, domain):
        cname = self.get_cname(domain)

        if not cname:
            return f"❌ {domain} (No CNAME)"

        service = self.detect_service(cname)

        if not service:
            return f"⚪ {domain} → {cname} (Unknown)"

        if self.check_takeover(domain, service):
            with self.lock:
                self.vuln_count += 1
            return f"🔥 {domain} → {service} TAKEOVER!"

        return f"✅ {domain} → {service}"


scanner = Scanner()

# ================= COMMAND =================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 Takeover Scanner Bot (Railway Ready)\n\n"
        "Commands:\n"
        "/scan domain.com\n"
        "Upload .txt file untuk mass scan"
    )

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: /scan domain.com")
        return

    domain = context.args[0].strip().lower()
    result = scanner.scan(domain)
    await update.message.reply_text(result)

# ================= FILE SCAN =================
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document

    if not doc.file_name.endswith(".txt"):
        await update.message.reply_text("❌ Upload file .txt")
        return

    file = await doc.get_file()
    path = "domains.txt"
    await file.download_to_drive(path)

    await update.message.reply_text("📂 File diterima, scanning...")

    with open(path) as f:
        domains = list(set(
            d.strip().lower()
            for d in f
            if d.strip() and not d.startswith("#")
        ))

    results = []
    vuln = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(scanner.scan, d) for d in domains]

        for future in as_completed(futures):
            res = future.result()
            results.append(res)

            if "🔥" in res:
                vuln.append(res)

    msg = (
        f"✅ Scan selesai!\n"
        f"Total: {len(domains)}\n"
        f"🔥 Vuln: {len(vuln)}\n\n"
    )

    if vuln:
        msg += "\n".join(vuln[:20])

    await update.message.reply_text(msg)

# ================= MAIN =================
def main():
    if not BOT_TOKEN:
        print("❌ BOT_TOKEN not set!")
        return

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))

    print("🤖 Bot running on Railway...")

    # Auto restart loop
    while True:
        try:
            app.run_polling()
        except Exception as e:
            print("Restarting bot:", e)

if __name__ == "__main__":
    main()