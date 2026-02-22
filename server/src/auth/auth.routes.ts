import ScalekitClient, { AuthenticationResponse } from "@scalekit-sdk/node";
import { Router } from "express";
import crypto from "crypto";
import { clearSessionCookie, setSessionCookie } from "./cookie";
import { requireAuth } from "./auth.middleware";

const router = Router();

function extractEnv(key: string){
    const getVal = process.env[key];

    if(!getVal) 
        throw new Error(`Missing Env, ${getVal}`);

    return getVal;
}

function makeScalekit(){
    return new ScalekitClient(
        extractEnv("SCALEKIT_ENV_URL"),
        extractEnv("SCALEKIT_CLIENT_ID"),
        extractEnv("SCALEKIT_CLIENT_SECRET")
    )
}

function getQueryString(value: unknown){
    if(typeof value === 'string')
        return value;

    return undefined;
}

function stateCookieOptions(){
    const isProd = process.env.Node_ENV === "production";

    return{
        httpOnly:true,
        secure:isProd,
        sameSite:"lax" as const,
        pzth:"/",
        maxAge:20*60*1000
    }
}

router.get("/login",(req,res)=>{
    try {
        const scalekit = makeScalekit();
        const state = crypto.randomBytes(16).toString('hex');
        res.cookie("sp_oath_state", state, stateCookieOptions());

        const redirectUri =`${extractEnv("BACKEND_URL")}/auth/callback`;
        const authorizationUrl=scalekit.getAuthorizationUrl(redirectUri,{
            scopes: ["openid", "profile", "email"],
            state
    })

    res.redirect(authorizationUrl);
        
    } catch (error) {
        res.status(500).json({
            success:false,
            message:"Error hai boss this kr lo"
        })
    }
});

router.get("/callback", async(req,res)=>{
    try {
            const code = getQueryString(req.query.code);
            const state = getQueryString(req.query.state);
            const error = getQueryString(req.query.error);

            if(error){
                return res.redirect(`${extractEnv("FRONTEND_URL")}/login=${error}`)
            }

            if(!code || !state){
                return res.status(400).send("code/staet is not available")
            }
            const expectedState = req.cookies?.["sp_outh_state"];
            if(!expectedState || expectedState!==state){
                return res.status(400).send("invalid state!!!");
            }
            //cookie nullification
            res.clearCookie("sp_oath_state", stateCookieOptions());
            const scalekit = makeScalekit();
            const redirectUri = `${extractEnv("BACKEND_URL")}/auth/callback`

            const authResult : AuthenticationResponse = await scalekit.authenticateWithCode(code, redirectUri);

            console.log(authResult,code, 'authReslt');

            if(!authResult.user){
                return res.status(500).send("missing user info");
            }
            setSessionCookie(res, {
                id: authResult.user.id,
                email: authResult.user.email,
                name: authResult.user.name,
                });

                return res.redirect(`${extractEnv("FRONTEND_URL")}/support`);

    } catch (error){
        res.status(500).json({
            success:false,
            message:"Error hai boss this kr lo"
        });   
    }
})

router.get("/me", requireAuth, (req, res) => {
  res.json({
    user: {
      id: req.user!.id,
      email: req.user!.email,
      name: req.user!.name,
    },
  });
});

router.post("/logout", (req, res) => {
  clearSessionCookie(res);

  res.json({ ok: true });
});

export default router;