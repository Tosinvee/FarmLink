/* eslint-disable prettier/prettier */
import { registerAs } from "@nestjs/config";

export default registerAs('mail', ()=>{
    return{
        service:process.env.MAIL_SERVICE,
        user:process.env.EMAIL,
        pass:process.env.APP_PASSWORD
    }
})