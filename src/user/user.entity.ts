/* eslint-disable prettier/prettier */
import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class User{
    @PrimaryGeneratedColumn('uuid')
    id:string;

    @Column({
        type:"varchar",
        length:98,
        nullable:true
    })
    firstname:string;
    @Column({
        type:"varchar",
        length:98,
        nullable:true
    })
    lastname:string;

    @Column({
        type:"varchar",
        length:98,
        nullable:true,
        unique:true
    })
    email:string

    @Column({
        type:"varchar",
        length:98,
        nullable:true
    })
    password:string

    @Column({default:false})
    emailVerified: boolean;

    @Column({nullable:true})
    verificationCode: string;

    @Column({default:'USER'})
    role:string;

    @Column({default:true})
    createdAt:Date;
}