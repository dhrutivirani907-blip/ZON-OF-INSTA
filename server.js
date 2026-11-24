const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!DATABASE_URL) throw new Error("DATABASE_URL environment variable is required");
if (!ADMIN_PASSWORD) throw new Error("ADMIN_PASSWORD environment variable is required");
if (!SESSION_SECRET) throw new Error("SESSION_SECRET environment variable is required");

const pool = new Pool({connectionString:DATABASE_URL,ssl:{rejectUnauthorized:false},max:10,idleTimeoutMillis:30000,connectionTimeoutMillis:10000});
app.set("trust proxy",1);
app.use(helmet({crossOriginResourcePolicy:false}));

const ALLOWED_ORIGINS=new Set([
 "https://dhrutivirani907-blip.github.io","http://localhost:3000","http://localhost:5173",
 "http://127.0.0.1:3000","http://127.0.0.1:5173"
]);
const corsOptions={origin(origin,cb){if(!origin||ALLOWED_ORIGINS.has(origin))return cb(null,true);return cb(new Error("Origin is not allowed by CORS"));},credentials:false,methods:["GET","POST","DELETE","OPTIONS"],allowedHeaders:["Content-Type","X-Account-Token","X-Admin-Token"],optionsSuccessStatus:204};
app.use(cors(corsOptions));app.options(/.*/,cors(corsOptions));app.use(express.json({limit:"20kb"}));

const generalLimiter=rateLimit({windowMs:60000,limit:120,standardHeaders:true,legacyHeaders:false});
const adminLimiter=rateLimit({windowMs:10*60000,limit:20,standardHeaders:true,legacyHeaders:false});
app.use("/api/",generalLimiter);

const MIN_AD_WATCH_MS=8000,AD_COOLDOWN_MS=30000,DAILY_AD_LIMIT=100,BREAK_EVERY=10,BREAK_MS=5*60000,MAX_AD_SESSION_MS=60*60000;
const OFFER_COST=30,OFFER_REWARD=7500000;
const activeAdSessions=new Map();
const COOKIE_NAME="job_account_session";

function normalizeName(v){return String(v||"").trim().replace(/\s+/g," ")}
function validName(n){return n.length>=2&&n.length<=40&&/^[\p{L}\p{N} ._-]+$/u.test(n)}
function sign(v){return crypto.createHmac("sha256",SESSION_SECRET).update(v).digest("hex")}
function makeToken(id){const p=`${id}.${Date.now()}`;return `${p}.${sign(p)}`}
function verifyToken(t){
 try{if(!t)return null;const p=t.split(".");if(p.length!==3)return null;const [id,issued,sig]=p;
  if(!/^\d+$/.test(id)||!/^\d+$/.test(issued))return null;
  if(Date.now()-Number(issued)>180*24*60*60*1000)return null;
  const expected=sign(`${id}.${issued}`);if(sig.length!==expected.length)return null;
  if(!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected)))return null;return Number(id);
 }catch{return null}
}
function setSessionCookie(res,id){res.cookie(COOKIE_NAME,makeToken(id),{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:process.env.NODE_ENV==="production"?"none":"lax",maxAge:180*24*60*60*1000,path:"/"})}
function clearSessionCookie(res){res.clearCookie(COOKIE_NAME,{path:"/"})}
app.use((req,res,next)=>{req.cookies={};const h=req.headers.cookie||"";for(const part of h.split(";")){const i=part.indexOf("=");if(i<0)continue;const k=part.slice(0,i).trim(),v=part.slice(i+1).trim();try{req.cookies[k]=decodeURIComponent(v)}catch{req.cookies[k]=v}}next()});
function getAccountId(req){return verifyToken(req.headers["x-account-token"])||verifyToken(req.cookies?.[COOKIE_NAME])}

async function getDailyState(id){
 const r=await pool.query(`SELECT ads_count,daily_ads_count,daily_ads_date,((NOW() AT TIME ZONE 'Asia/Kolkata')::date) AS today FROM job_accounts WHERE id=$1 AND is_active=TRUE`,[id]);
 if(!r.rows[0])return null;const row=r.rows[0];
 if(String(row.daily_ads_date)!==String(row.today)){
  const x=await pool.query(`UPDATE job_accounts SET daily_ads_count=0,daily_ads_date=((NOW() AT TIME ZONE 'Asia/Kolkata')::date),updated_at=NOW() WHERE id=$1 RETURNING ads_count,daily_ads_count,daily_ads_date`,[id]);
  return x.rows[0]||null;
 }return row;
}
async function getHistory(id){
 const r=await pool.query(`SELECT ticket_cost,reward_coins,completed_at FROM super_offer_history WHERE account_id=$1 ORDER BY completed_at DESC LIMIT 30`,[id]);
 return r.rows.map(x=>({ticketCost:Number(x.ticket_cost),rewardCoins:Number(x.reward_coins),completedAt:x.completed_at}));
}
async function accountPayload(id){
 const r=await pool.query(`SELECT id,name,ads_count,daily_ads_count,ticket_balance,coin_balance,referrals_count FROM job_accounts WHERE id=$1 AND is_active=TRUE`,[id]);
 if(!r.rows[0])return null;const x=r.rows[0];
 return {id:x.id,name:x.name,adsCount:Number(x.ads_count),dailyAdsCount:Number(x.daily_ads_count||0),ticketBalance:Number(x.ticket_balance||0),pendingOfferCount:Number(x.pending_offer_count||0),coinBalance:Number(x.coin_balance||0),referralsCount:Number(x.referrals_count||0),superOfferHistory:await getHistory(id)};
}
async function requireAccount(req,res,next){
 const id=getAccountId(req);if(!id)return res.status(401).json({ok:false,error:"Account session expired. Please enter your name again."});
 try{
  const state=await getDailyState(id);if(!state)return res.status(401).json({ok:false,error:"Account not found."});
  const a=await accountPayload(id);if(!a){clearSessionCookie(res);return res.status(401).json({ok:false,error:"Account not found."})}
  req.account=a;next();
 }catch(e){console.error(e);res.status(500).json({ok:false,error:"Server error."})}
}
function requireAdmin(req,res,next){
 const token=String(req.headers["x-admin-token"]||"");if(!token||token.length<20)return res.status(401).json({ok:false,error:"Admin authentication required."});
 const expected=sign("admin:"+ADMIN_PASSWORD);
 try{if(token.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(token),Buffer.from(expected)))return res.status(401).json({ok:false,error:"Invalid admin session."})}catch{return res.status(401).json({ok:false,error:"Invalid admin session."})}
 next();
}

async function initDb(){
 await pool.query(`CREATE TABLE IF NOT EXISTS job_accounts(
  id BIGSERIAL PRIMARY KEY,name VARCHAR(40) NOT NULL,name_key VARCHAR(40) NOT NULL UNIQUE,
  ads_count BIGINT NOT NULL DEFAULT 0 CHECK(ads_count>=0),
  daily_ads_count INTEGER NOT NULL DEFAULT 0 CHECK(daily_ads_count>=0),
  daily_ads_date DATE NOT NULL DEFAULT ((NOW() AT TIME ZONE 'Asia/Kolkata')::date),
  ticket_balance BIGINT NOT NULL DEFAULT 0 CHECK(ticket_balance>=0),
  pending_offer_count INTEGER NOT NULL DEFAULT 0 CHECK(pending_offer_count>=0),
  coin_balance BIGINT NOT NULL DEFAULT 0 CHECK(coin_balance>=0),
  referrals_count INTEGER NOT NULL DEFAULT 0 CHECK(referrals_count>=0),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),last_ad_attempt_at TIMESTAMPTZ
 )`);
 await pool.query(`ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS ticket_balance BIGINT NOT NULL DEFAULT 0`);
 await pool.query(`ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS pending_offer_count INTEGER NOT NULL DEFAULT 0`);
 await pool.query(`ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS coin_balance BIGINT NOT NULL DEFAULT 0`);
 await pool.query(`ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS referrals_count INTEGER NOT NULL DEFAULT 0`);
 await pool.query(`ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS last_ad_attempt_at TIMESTAMPTZ`);
 await pool.query(`ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS daily_ads_count INTEGER NOT NULL DEFAULT 0`);
 await pool.query(`ALTER TABLE job_accounts ADD COLUMN IF NOT EXISTS daily_ads_date DATE NOT NULL DEFAULT ((NOW() AT TIME ZONE 'Asia/Kolkata')::date)`);
 await pool.query(`CREATE TABLE IF NOT EXISTS super_offer_history(
  id BIGSERIAL PRIMARY KEY,account_id BIGINT NOT NULL REFERENCES job_accounts(id) ON DELETE CASCADE,
  ticket_cost BIGINT NOT NULL,reward_coins BIGINT NOT NULL,completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 )`);
 await pool.query(`CREATE INDEX IF NOT EXISTS job_accounts_created_idx ON job_accounts(created_at DESC)`);
 await pool.query(`CREATE INDEX IF NOT EXISTS super_offer_history_account_idx ON super_offer_history(account_id,completed_at DESC)`);
}

app.get("/",(req,res)=>res.json({status:"Active",app:"BabyDoge Rewards Backend",database:"Connected API",version:"3.0.0"}));
app.get("/api/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true,status:"healthy"})}catch{res.status(503).json({ok:false,status:"database_unavailable"})}});

app.get("/api/session",async(req,res)=>{
 const id=getAccountId(req);if(!id)return res.json({ok:true,hasSession:false});
 try{const a=await accountPayload(id);if(!a){clearSessionCookie(res);return res.json({ok:true,hasSession:false})}res.json({ok:true,hasSession:true})}catch{res.status(500).json({ok:false,error:"Server error."})}
});

app.post("/api/account",async(req,res)=>{
 const name=normalizeName(req.body?.name);if(!validName(name))return res.status(400).json({ok:false,error:"Please enter a valid name (2-40 characters)."});
 const key=name.toLocaleLowerCase("en-US");
 try{
  const exists=await pool.query("SELECT id FROM job_accounts WHERE name_key=$1",[key]);
  if(exists.rows[0])return res.status(409).json({ok:false,error:"This name already has an account. Please use Check Account."});
  const created=await pool.query(`INSERT INTO job_accounts(name,name_key) VALUES($1,$2) RETURNING id`,[name,key]);
  const sessionToken=makeToken(created.rows[0].id);setSessionCookie(res,created.rows[0].id);
  res.status(201).json({ok:true,sessionToken,account:await accountPayload(created.rows[0].id)});
 }catch(e){if(e.code==="23505")return res.status(409).json({ok:false,error:"This name already has an account."});console.error(e);res.status(500).json({ok:false,error:"Could not create account."})}
});

app.post("/api/account/check",async(req,res)=>{
 const name=normalizeName(req.body?.name);if(!validName(name))return res.status(400).json({ok:false,error:"Please enter a valid name."});
 try{
  const r=await pool.query(`SELECT id FROM job_accounts WHERE name_key=$1 AND is_active=TRUE`,[name.toLocaleLowerCase("en-US")]);
  if(!r.rows[0])return res.status(404).json({ok:false,error:"No account was found with this name."});
  const id=r.rows[0].id,sessionToken=makeToken(id);setSessionCookie(res,id);
  res.json({ok:true,sessionToken,account:await accountPayload(id)});
 }catch(e){console.error(e);res.status(500).json({ok:false,error:"Could not check account."})}
});
app.get("/api/account/me",requireAccount,(req,res)=>res.json({ok:true,account:req.account}));

app.post("/api/account/me/start-ad",requireAccount,async(req,res)=>{
 const now=Date.now();
 try{
  const r=await pool.query(`SELECT last_ad_attempt_at,daily_ads_count,daily_ads_date,((NOW() AT TIME ZONE 'Asia/Kolkata')::date) AS today FROM job_accounts WHERE id=$1 AND is_active=TRUE`,[req.account.id]);
  if(!r.rows[0])return res.status(404).json({ok:false,error:"Account not found."});
  let daily=Number(r.rows[0].daily_ads_count||0);
  if(String(r.rows[0].daily_ads_date)!==String(r.rows[0].today)){daily=0;await pool.query(`UPDATE job_accounts SET daily_ads_count=0,daily_ads_date=((NOW() AT TIME ZONE 'Asia/Kolkata')::date),updated_at=NOW() WHERE id=$1`,[req.account.id])}
  if(daily>=DAILY_AD_LIMIT)return res.status(429).json({ok:false,error:"Daily ad limit reached. Maximum 100 ads per day."});
  const last=r.rows[0].last_ad_attempt_at?new Date(r.rows[0].last_ad_attempt_at).getTime():0;
  if(daily>0&&daily%BREAK_EVERY===0){const rem=Math.max(0,BREAK_MS-(now-last));if(rem>0)return res.status(429).json({ok:false,error:`5-minute break active. Wait ${Math.ceil(rem/1000)} seconds.`})}
  const rem=Math.max(0,AD_COOLDOWN_MS-(now-last));if(rem>0)return res.status(429).json({ok:false,error:`Cooldown active. Wait ${Math.ceil(rem/1000)} seconds.`});
  const token=crypto.randomBytes(32).toString("hex");
  await pool.query(`UPDATE job_accounts SET last_ad_attempt_at=NOW(),updated_at=NOW() WHERE id=$1`,[req.account.id]);
  activeAdSessions.set(String(req.account.id),{token,startedAt:now,used:false});
  res.json({ok:true,adToken:token});
 }catch(e){console.error(e);res.status(500).json({ok:false,error:"Could not start ad session."})}
});

app.post("/api/account/me/cancel-ad",requireAccount,async(req,res)=>{
 const key=String(req.account.id),s=activeAdSessions.get(key),token=String(req.body?.adToken||"");
 if(!s||!token||token!==s.token||s.used)return res.status(400).json({ok:false,error:"Ad session is invalid."});
 s.used=true;activeAdSessions.delete(key);
 try{await pool.query(`UPDATE job_accounts SET last_ad_attempt_at=NOW(),updated_at=NOW() WHERE id=$1`,[req.account.id]);res.json({ok:true})}
 catch(e){console.error(e);res.status(500).json({ok:false,error:"Could not close ad session."})}
});

app.post("/api/account/me/increment-ad",requireAccount,async(req,res)=>{
 const key=String(req.account.id),s=activeAdSessions.get(key),token=String(req.body?.adToken||"");
 if(!s||!token||token!==s.token||s.used)return res.status(400).json({ok:false,error:"Ad session is invalid or already used. Please open the ad again."});
 if(Date.now()-s.startedAt<MIN_AD_WATCH_MS)return res.status(400).json({ok:false,error:"Watch Ads minimum 8 seconds."});
 if(Date.now()-s.startedAt>MAX_AD_SESSION_MS){activeAdSessions.delete(key);return res.status(400).json({ok:false,error:"Ad session expired. Please open the ad again."});
 }
 s.used=true;activeAdSessions.delete(key);
 try{
  const r=await pool.query(`UPDATE job_accounts SET ads_count=ads_count+1,daily_ads_count=daily_ads_count+1,
   daily_ads_date=((NOW() AT TIME ZONE 'Asia/Kolkata')::date),ticket_balance=ticket_balance+1,
   last_ad_attempt_at=NOW(),updated_at=NOW()
   WHERE id=$1 AND is_active=TRUE AND daily_ads_count<$2
   AND daily_ads_date=((NOW() AT TIME ZONE 'Asia/Kolkata')::date)
   RETURNING id`,[req.account.id,DAILY_AD_LIMIT]);
  if(!r.rows[0])return res.status(429).json({ok:false,error:"Daily ad limit reached. Maximum 100 ads per day."});
  res.json({ok:true,message:"1 ticket added to your balance.",account:await accountPayload(req.account.id)});
 }catch(e){console.error(e);res.status(500).json({ok:false,error:"Could not update ad count."})}
});

app.post("/api/account/me/super-offer/unlock",requireAccount,async(req,res)=>{
 const r=await pool.query(`UPDATE job_accounts SET ticket_balance=ticket_balance-$1,pending_offer_count=pending_offer_count+1,updated_at=NOW()
  WHERE id=$2 AND is_active=TRUE AND ticket_balance >= $1 AND pending_offer_count=0 RETURNING id`,[OFFER_COST,req.account.id]);
 if(!r.rows[0])return res.status(400).json({ok:false,error:"You need 30 tickets to unlock this Super Offer."});
 res.json({ok:true,message:"Super Offer unlocked. Claim your coins.",account:await accountPayload(req.account.id)});
});

app.post("/api/account/me/super-offer/claim",requireAccount,async(req,res)=>{
 const client=await pool.connect();
 try{
  await client.query("BEGIN");
  const r=await client.query(`UPDATE job_accounts SET pending_offer_count=pending_offer_count-1,coin_balance=coin_balance+$1,updated_at=NOW()
   WHERE id=$2 AND is_active=TRUE AND pending_offer_count>0 RETURNING id`,[OFFER_REWARD,req.account.id]);
  if(!r.rows[0]){await client.query("ROLLBACK");return res.status(400).json({ok:false,error:"No unlocked Super Offer is waiting to be claimed."})}
  await client.query(`INSERT INTO super_offer_history(account_id,ticket_cost,reward_coins) VALUES($1,$2,$3)`,[req.account.id,OFFER_COST,OFFER_REWARD]);
  await client.query("COMMIT");
  res.json({ok:true,message:"Coin claimed.",account:await accountPayload(req.account.id)});
 }catch(e){try{await client.query("ROLLBACK")}catch{}console.error(e);res.status(500).json({ok:false,error:"Could not claim Super Offer coin."})}finally{client.release()}
});

app.post("/api/logout",(req,res)=>{clearSessionCookie(res);res.json({ok:true})});

app.post("/api/admin/login",adminLimiter,(req,res)=>{
 const p=String(req.body?.password||"");if(!p)return res.status(400).json({ok:false,error:"Password is required."});
 const a=Buffer.from(p),b=Buffer.from(ADMIN_PASSWORD);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({ok:false,error:"Incorrect admin password."});
 res.json({ok:true,adminToken:sign("admin:"+ADMIN_PASSWORD)});
});

app.get("/api/admin/users",requireAdmin,async(req,res)=>{
 try{
  const r=await pool.query(`SELECT a.id,a.name,a.ads_count,a.referrals_count,
    (SELECT COUNT(*) FROM super_offer_history h WHERE h.account_id=a.id) AS super_offers_completed
    FROM job_accounts a WHERE a.is_active=TRUE ORDER BY a.created_at DESC`);
  res.json({ok:true,users:r.rows.map(x=>({id:x.id,name:x.name,adsCount:Number(x.ads_count),superOffersCompleted:Number(x.super_offers_completed),referralsCount:Number(x.referrals_count||0)}))});
 }catch(e){console.error(e);res.status(500).json({ok:false,error:"Could not load users."})}
});

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({ok:false,error:"Unexpected server error."})});
initDb().then(()=>app.listen(PORT,()=>console.log(`BabyDoge Rewards backend running on port ${PORT}`))).catch(e=>{console.error("Database initialization failed:",e);process.exit(1)});
