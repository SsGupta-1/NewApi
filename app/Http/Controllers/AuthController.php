<?php

namespace App\Http\Controllers;

use App\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Auth;
use Hash;
use Validator;
use Str;
use DB;
use Mail;

class AuthController extends Controller
{
    public function signup(Request $request){

        $rules = [
            'name' => 'required|regex:/(^([a-zA-z]+)(\d+)?$)/u',
            'phone' => 'required_with:email|min:11|numeric',
            'phone' => 'max:15|unique:users,phone',
            "email"=>'required|max:32|email|unique:users,email',
            'password' => 'required|string|min:4|confirmed'
        ];
        $validator = Validator::make($request->all(),$rules);

        if($validator->fails()){
            return response()->json($validator->errors(),400); // 400 = Bad Request
        }

        $user = new User([
            'name' => $request->name,
            'phone' => $request->phone,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $user->save();
        $tokenResult = $user->createToken('my token');
        $token = $tokenResult->token;
        $token->save();
        return response()->json([ 
            'message' => 'Successfully created user!' ,
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer'
        ], 201);  


        
    }



    public function login(Request $request){

        if(Auth::check()==true){
            return response()->json([ 'message' => 'you are already login' ], 401);
        }
        else{

        $rules = [
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ];
        $validator = Validator::make($request->all(),$rules);

        if($validator->fails()){
            return response()->json($validator->errors(),400); // 400 = Bad Request
        }
        
            $credentials = request(['email', 'password']);
        if(!Auth::attempt($credentials))
            return response()->json([ 'message' => 'Unauthorized! Your Credentials not match' ], 401);

        $user = $request->user();
       
        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        if ($request->remember_me)
            $token->expires_at = Carbon::now()->AddDays(2);
        $token->save();

        return response()->json([
            'message' => 'Successfully Login!',
          
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse(
                $tokenResult->token->expires_at
            )->toDateTimeString()
            ]);

        }
        
    }



    public function logout(Request $request){

        // $rules = [
        //     'token' => 'required',
        // ];
        // $validator = Validator::make($request->all(),$rules);

        // if($validator->fails()){
        //     return response()->json($validator->errors(),400); // 400 = Bad Request
        // }

        $request->user()->token()->revoke();
        
        return response()->json([
            'message' => 'Successfully logged out',
            
            
        ]);
    }



                public function user(Request $request){

                    // return Auth::user();

                    return response()->json($request->user());
                }


    public function forget(Request $request){
        
        $email = $request->email;

        if(User::where('email',$email)->doesntExist()){

            return response([
                'message' => 'User Does not exist!',
            ],404);
        }

        
        //  $token = $email->createToken('my token')->accessToken;
        // $token = $tokenResult->token;
        // $token->save();
        $token = Str::random(10);

        try{
            DB::table('password_resets')->insert([
                'email'=> $email,
                'token' => $token,
            ]); 

        //     Mail::to($request->email)->send();
        // $notification = array(
        //     'message' => 'Thanks! We shall get back to you soon.', 
        //     'alert-type' => 'success'
        // );
           
        Mail::send('forgetmail', ['token' => $token] ,function($message) use ($email){
                $message->to($email);
                $message->subject('Reset your password');

            });

            return response([
                'message' => 'Reset link sent Successfully!',
            ],200);


        }catch(\Exception $exception){
            return response([
                'message' => $exception->getMessage(),
            ],404);

        }
        
    }


            public function resetpassword(Request $request){

                $rules = [
                    'token' => 'required',
                    'password' => 'required|string|confirmed',
                
                ];
                $validator = Validator::make($request->all(),$rules);
        
                if($validator->fails()){
                    return response()->json($validator->errors(),400); // 400 = Bad Request
                }

               
             $token = $request->token;

            $result = DB::table('password_resets')->where('token',$token)->first();

                if(!$result){
                    return response([
                        'message' => 'invalid token',

                    ],400);
                }

                $user = User::where('email',$result->email)->first();

                if(!$user){
                    return response([
                        'message ' => 'user doesn\'t exist!'
                    ],404);
                }
                $user->password = Hash::make($request->password);
                $user->save();
                return response([
                    'message ' => 'Password reset successfull'
                ],200);
                
            }

}



