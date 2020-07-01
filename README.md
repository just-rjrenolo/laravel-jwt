## Require jwt
- composer require tymon/jwt-auth:dev-develop --prefer-source

## Config/App
### add to providers
- Tymon\JWTAuth\Providers\LaravelServiceProvider::class,

### add to facades
- 'JWTAuth' => Tymon\JWTAuth\Facades\JWTAuth::class,
- 'JWTFactory' => Tymon\JWTAuth\Facades\JWTFactory::class,

## publish the config file for JWT
- php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"

## generate JWT secret
- php artisan jwt:secret

## configure User model to use JWT

```PHP
<?php
    namespace App;
    use Illuminate\Notifications\Notifiable;
    use Illuminate\Foundation\Auth\User as Authenticatable;
    use Tymon\JWTAuth\Contracts\JWTSubject;
    class User extends Authenticatable implements JWTSubject{
        use Notifiable;
        /**
         * The attributes that are mass assignable.
         *
         * @var array
         */
        protected $fillable = [
            'name', 'email', 'password',
        ];
        /**
         * The attributes that should be hidden for arrays.
         *
         * @var array
         */
        protected $hidden = [
            'password', 'remember_token',
        ];
        public function getJWTIdentifier(){
            return $this->getKey();
        }
        public function getJWTCustomClaims(){
            return [];
        }
    }
```

We have defined the User model to implement JWTSubject. We also defined two methods to return the JWTIdentifier and JWTCustomClaims. Custom claims are used in generating the JWT token.


# Controllers
- php artisan make:controller UserController 
- php artisan make:controller DataController


## User Controller
```PHP
 <?php
    namespace App\Http\Controllers;
    use App\User;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Hash;
    use Illuminate\Support\Facades\Validator;
    use JWTAuth;
    use Tymon\JWTAuth\Exceptions\JWTException;
    class UserController extends Controller{
        public function authenticate(Request $request){
            $credentials = $request->only('email', 'password');
            try {
                if (! $token = JWTAuth::attempt($credentials)) {
                    return response()->json(['error' => 'invalid_credentials'], 400);
                }
            } catch (JWTException $e) {
                return response()->json(['error' => 'could_not_create_token'], 500);
            }
            return response()->json(compact('token'));
        }
        public function register(Request $request){
                $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:6|confirmed',
            ]);

            if($validator->fails()){
                    return response()->json($validator->errors()->toJson(), 400);
            }

            $user = User::create([
                'name' => $request->get('name'),
                'email' => $request->get('email'),
                'password' => Hash::make($request->get('password')),
            ]);

            $token = JWTAuth::fromUser($user);

            return response()->json(compact('user','token'),201);
        }

        public function getAuthenticatedUser(){
            try {
                if (! $user = JWTAuth::parseToken()->authenticate()) {
                    return response()->json(['user_not_found'], 404);
                }
            } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
                    return response()->json(['token_expired'], $e->getStatusCode());
            } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
                    return response()->json(['token_invalid'], $e->getStatusCode());
            } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
                    return response()->json(['token_absent'], $e->getStatusCode());
            }
            return response()->json(compact('user'));
    }
}
```

The authenticate method attempts to log a user in and generates an authorization token if the user is found in the database. It throws an error if the user is not found or if an exception occurred while trying to find the user.

The register method validates a user input and creates a user if the user credentials are validated. The user is then passed on to JWTAuth to generate an access token for the created user. This way, the user would not need to log in to get it.

We have the getAuthenticatedUser method which returns the user object based on the authorization token that is passed.

## Data Controller
```PHP
 <?php
    namespace App\Http\Controllers;
    use Illuminate\Http\Request;
    class DataController extends Controller{
        public function open(){
            $data = "This data is open and can be accessed without the client being authenticated";
            return response()->json(compact('data'),200);
        }
        public function closed(){
            $data = "Only authorized users can see this";
            return response()->json(compact('data'),200);
        }
    }
```

# Creating Midlleware
- php artisan make:middleware JwtMiddleware

## app/Http/Middleware/JwtMiddleware

```PHP
<?php
    namespace App\Http\Middleware;
    use Closure;
    use JWTAuth;
    use Exception;
    use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;

    class JwtMiddleware extends BaseMiddleware{

        /**
         * Handle an incoming request.
         *
         * @param  \Illuminate\Http\Request  $request
         * @param  \Closure  $next
         * @return mixed
         */
        public function handle($request, Closure $next){
            try {
                $user = JWTAuth::parseToken()->authenticate();
            } catch (Exception $e) {
                if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException){
                    return response()->json(['status' => 'Token is Invalid']);
                }else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException){
                    return response()->json(['status' => 'Token is Expired']);
                }else{
                    return response()->json(['status' => 'Authorization Token not found']);
                }
            }
            return $next($request);
        }
    }
```
This middleware extends Tymon\JWTAuth\Http\Middleware\BaseMiddleware, with this, we can catch token errors and return appropriate error codes to our users.

## register JWTMiddleware in Kernel.php
```PHP
protected $routeMiddleware = [
    'jwt.verify' => \App\Http\Middleware\JwtMiddleware::class,
];
```

## routes under api.php
```PHP
Route::post('register', 'UserController@register');
Route::post('login', 'UserController@authenticate');
Route::get('open', 'DataController@open');

Route::group(['middleware' => ['jwt.verify']], function() {
    Route::get('user', 'UserController@getAuthenticatedUser');
    Route::get('closed', 'DataController@closed');
});
```

#FORM DATA
`/api/register`
- name
- email
- password
- password_confirmation

`/api/login`
- email
-password

`/api/open`
- this is an open route

`/api/closed`
```
Header 
Authorization : Bearer Token
```

```
Endpoint : 127.0.0.1:8000/api/user
Method: GET
Payload:

Authorization: Bearer insert_user_token_here
```

```
Endpoint : 127.0.0.1:8000/api/user
Method: GET
Payload:

Authorization: Bearer thistokeniswrong
```