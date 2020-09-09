import "reflect-metadata"
import { MikroORM } from "@mikro-orm/core";
import { __prod__ } from "./constants";
import microConfig from './mikro-orm.config'
import express from 'express';
import {ApolloServer} from 'apollo-server-express'
import {buildSchema} from 'type-graphql';
import { HelloResolver } from "./resolvers/hello";
import { PostResolver } from "./resolvers/post";
import { UserResolver } from "./resolvers/user";
import redis from 'redis';
import session from 'express-session';
import connectRedis from 'connect-redis'
import { MyContext } from "./types";



const main = async() =>{
    const orm = await MikroORM.init(microConfig);
    await orm.getMigrator().up();

    const app = express();
    const RedisStore = connectRedis(session);
    const redisClient = redis.createClient();

    app.use(
    session({
        name: 'qid',
        store: new RedisStore({ 
            client: redisClient,
            disableTouch: true

         }),
         cookie:{
             maxAge: 1000 * 60 * 60 * 24 * 365 * 10, // 10 Years
             httpOnly: true,
             sameSite: 'lax', //protects csrf
             secure: __prod__ //cookie works only in https
         },
        secret: 'glagfjldksgjl',//should make this env var
        saveUninitialized: false,
        resave: false,
    })
    )
    const apolloServer = new ApolloServer({
        schema: await buildSchema({
            resolvers: [HelloResolver,PostResolver,UserResolver],
            validate: false,
        }),
        context: ({req, res}):MyContext => ({em: orm.em, req, res})
    });

    apolloServer.applyMiddleware({app});

    app.listen(4000, () => {
        console.log('server started at localhost:4000');
    })
    // app.get('/', (_, res) =>{
    //     res.send("hello");
    // })
    // const post = orm.em.create(Post, {title: 'my first post'})
    // await orm.em.persistAndFlush(post)
    // const posts = await orm.em.find(Post,{});
    // console.log(posts);
};

main().catch(err => {
    console.error(err);
    
});