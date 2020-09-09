import { Resolver, Mutation, Arg, InputType, Field, Ctx, ObjectType, Query } from "type-graphql";
import { User } from "../entities/User"
import { MyContext } from "../types"
import argon2 from "argon2"
@InputType()
class UsernamePasswordInput{
    @Field()
    username: string
    @Field()
    password:string
}

@ObjectType()
class FieldError{
    @Field()
    field: string;
    @Field()
    message: string;
}

@ObjectType()
class UserResponse{
    @Field(() => [FieldError], {nullable: true})
    errors?: FieldError[]

    @Field(() => User, {nullable: true})
    user?:User
}

@Resolver()
export class UserResolver{
    @Query(()=> User, {nullable: true})
    me(
        @Ctx() { req ,em}: MyContext
    ){
        if (!req.session!.userId){
            return null
        }
        return em.findOne(User, {id: req.session!.userId})
    }
    @Mutation(() => UserResponse)
    async register(
        @Arg('options', () => UsernamePasswordInput) options: UsernamePasswordInput,
        @Ctx() {em, req}: MyContext
    ):Promise<UserResponse> {
        if (options.username.length<=2){
            return{
                errors:[{
                    field: "Username",
                    message: "Username too short"
                }]
            };
        }
        if (options.password.length<=3){
            return{
                errors:[{
                    field: "Password",
                    message: "Password too short"
                }]
            };
        }
        const hashedPassword = await argon2.hash(options.password)
        const user = em.create(User, {
            username: options.username,
            password: hashedPassword    
        });
        try{
            await em.persistAndFlush(user);
        }catch(err){
            if (err.code === "23505"){
                return{
                    errors:[{
                        field: "User",
                        message: "username already taken"
                    }]
                };
            }else{
                console.log("message: ", err.message);
                
            }

        }
        req.session!.userId = user.id
        return {user,}
    }

    @Mutation(() => UserResponse)
    async login(
        @Arg('options', () => UsernamePasswordInput) options: UsernamePasswordInput,
        @Ctx() {em, req}: MyContext
    ): Promise<UserResponse> {
        const user = await em.findOne(User,{username: options.username});
        if (!user){
            return {
                errors: [
                   {
                    field: "username",
                    message: "username does not exist"
                },
            ]
            };
        }
        const valid = await argon2.verify(user.password, options.password)
        if (!valid){
            return {
                errors: [
                   {
                    field: "password",
                    message: "Invalid Login"
                },
            ]
            };
        }
        req.session!.userId = user.id;
        return {
            user,
        };
    }
}

    