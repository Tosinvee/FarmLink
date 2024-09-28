/* eslint-disable prettier/prettier */
import { registerAs } from "@nestjs/config";

export default registerAs('database', ()=>({
    host:process.env.DATABASE_HOST,
    port:parseInt(process.env.DATABASE_PORT) ,
    user:process.env.DATABASE_USER ,
    password:String(process.env.DATABASE_PASSWORD),
    name:process.env.DATABASE_NAME ,
    synchronize:process.env.DATABASE_SYNC,
    autoLoaEntities:process.env.DATABASE_AUTOLOAD,
}))