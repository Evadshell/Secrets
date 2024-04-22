import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
const { Pool } = pg;
import { db } from "@vercel/postgres";
import ejs from "ejs";
import path from "path"; 
const __dirname = path.dirname(new URL(import.meta.url).pathname);
const pool = new Pool({
  connectionString: process.env.POSTGRES_URL ,
})
const app = express();
const port = 3000;
const saltRounds = 10;
env.config();


app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(express.static(path.join(__dirname,'public')));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views")); 

app.use(passport.initialize());
app.use(passport.session());

// const db = new pg.Client({
//   user: process.env.PG_USER,
//   host: process.env.PG_HOST,
//   database: process.env.PG_DATABASE,
//   password: process.env.PG_PASSWORD,
//   port: process.env.PG_PORT,
// });
const db1= await db.connect();
// db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {

const result= await db1.query("SELECT * FROM userdata WHERE email=$1",[req.user.email]);
    const secret = result.rows[0].secret;
    res.render("secrets.ejs",{secret:secret});

  } else {
    res.redirect("/login");
  }
});
app.get("/submit",(req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit.ejs");
  }
  else {
    res.redirect("/login");
  }

})
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);
app.get("/users", async (req,res)=>{
  if (req.isAuthenticated()) {
    const current_email = req.user.email;
    console.log(current_email);

    try{
        const data = await db1.query("SELECT * FROM requests WHERE requested_mail = $1",[current_email]);
      
        const date = data.rows;

      console.log(date.length);
      
         const result= await db1.query("SELECT email FROM userdata ");
        var users = result.rows;
        users = users.filter(item => item.email !== current_email);
        // console.log(users);
        res.render("users.ejs",{users:users,data:date});
    }catch(err){
      console.log(err);
    }
  
    
      } else {
        res.redirect("/login");
      }
})
app.get("/requests",async (req,res)=>{
  if (req.isAuthenticated()) {
    const current_email = req.user.email;
    console.log(current_email);
    const result= await db1.query("SELECT * FROM requests WHERE requested_to_mail=$1 ",[current_email]);
        var users = result.rows;
        users = users.filter(item => item.email !== current_email);
        // console.log(users);
        res.render("request.ejs",{users:users});

      } else {
        res.redirect("/login");
      }
})
app.post("/requests",async(req,res)=>{
  const access= req.body.access;
  const requested_to_mail = req.user.email;
  const requested_mail = req.body.mailto_value;
  console.log(access,requested_mail,requested_to_mail);
  try{
    if(access==='yes'){
      const secret = await db1.query("SELECT secret FROM userdata WHERE email = $1",[requested_to_mail])
      const secret1 = secret.rows[0].secret;
      const result = await db1.query("UPDATE requests SET (secrets,access) = ($1,$2) WHERE (requested_mail,requested_to_mail) =($3,$4)",[secret1,access,requested_mail[0],requested_to_mail]);
  res.redirect("/requests")
    }
    else if(access==='no'){
      const result = await db1.query("DELETE FROM  requests WHERE (requested_mail,requested_to_mail) =($1,$2)",[requested_mail[0],requested_to_mail]);
      res.redirect("/requests")
    }
    
  }
  catch(err){
    console.log(err);
  }

})
app.post("/users",async (req,res)=>{
  const requested_mail = req.user.email;
  const access = req.body.access_value;
  const requested_to_mail = req.body.mailto_value;
  console.log(requested_mail,access,requested_to_mail)
  try{
    const result = await  db1.query("INSERT INTO requests (requested_mail,requested_to_mail,access) VALUES ($1,$2,$3)",[requested_mail,requested_to_mail,access]);
   
  }
  catch(err){
    console.log(err);
  }
  
  console.log("test");
  res.redirect("/users");
})
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db1.query("SELECT * FROM userdata WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db1.query(
            "INSERT INTO userdata (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


app.post("/submit",async(req,res)=>{
  const secret = req.body.secret;
  console.log(secret,req.user);
  try{
    const result = await db1.query("UPDATE userdata SET secret = $1  WHERE email = $2",[secret,req.user.email]);
    res.redirect("/secrets");
  }catch(err){
    console.log(err);
  }
})
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db1.query("SELECT * FROM userdata WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://secrets-phi.vercel.app/auth/google/secrets",
      // callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db1.query("SELECT * FROM userdata WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db1.query(
            "INSERT INTO userdata (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


