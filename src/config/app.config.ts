/* eslint-disable prettier/prettier */
import { registerAs } from "@nestjs/config";

export default registerAs('appCOnfig', ()=>({
    environment:process.env.NODE_ENV || 'production'
    })
)