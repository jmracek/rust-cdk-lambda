import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as apigatewayv2 from "@aws-cdk/aws-apigatewayv2-alpha";
import * as path from "path";
import { HttpLambdaIntegration } from '@aws-cdk/aws-apigatewayv2-integrations-alpha';
import { Construct } from 'constructs';

export class UserAuthenticationStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        const userAuthenticationTable = new dynamodb.TableV2(this, 'UserAuthentication', {
            tableName: 'UserAuthentication',
            partitionKey: { name: 'username', type: dynamodb.AttributeType.STRING },
            deletionProtection: false,
            removalPolicy: cdk.RemovalPolicy.DESTROY,
            replicas: [],
        });

        const authenticationHandler = new lambda.Function(this, "AuthenticationHandler", {
            runtime: lambda.Runtime.PROVIDED_AL2023,
            code: lambda.Code.fromAsset(path.join(
                __dirname,
                "..",
                "..",
                "target/lambda/session/",
            )),
            handler: "bootstrap",
            functionName: "session",
        });
        
        const userHandler = new lambda.Function(this, "UserHandler", {
            runtime: lambda.Runtime.PROVIDED_AL2023,
            code: lambda.Code.fromAsset(path.join(
                __dirname,
                "..",
                "..",
                "target/lambda/user/"
            )),
            handler: "bootstrap",
            functionName: "user",
        });

        userAuthenticationTable.grantReadData(authenticationHandler);
        userAuthenticationTable.grantReadWriteData(userHandler);

        const authenticationHttpIntegration = new HttpLambdaIntegration('AuthenticationHttpLambdaIntegration', authenticationHandler);
        const userHttpIntegration = new HttpLambdaIntegration('UserHttpLambdaIntegration', userHandler);

        const httpApi = new apigatewayv2.HttpApi(this, "authentication-api");

        httpApi.addRoutes({
            path: '/session',
            methods: [
                apigatewayv2.HttpMethod.POST,
            ],
            integration: authenticationHttpIntegration,
        });

        httpApi.addRoutes({
            path: '/user',
            methods: [
                apigatewayv2.HttpMethod.POST,
            ],
            integration: userHttpIntegration,
        });
    }
}
