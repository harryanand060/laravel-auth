#laravel-auth-operation 

#version:
         8
#database: 
        mysql

##Step 1: Install Laravel

     composer create-project --prefer-dist laravel/laravel blog
   
##Step 2: Install Package

     composer require laravel/passport
  
##open config/app.php file and add service provider.

    config/app.php
    'providers' =>[
    Laravel\Passport\PassportServiceProvider::class,
    ],

##Step 3: Run Migration and Install

    php artisan migrate

##we need to install a passport using the command, Using passport:install command, it will create token keys for security

    php artisan passport:install

##Step 4: Passport Configuration

    we have to do the configuration on three place model, service provider and auth config file. So you have to just follow change on that file.
    In model, we added HasApiTokens class of Passport,
    In AuthServiceProvider we added “Passport::routes()”,
    In auth.php, we added API auth configuration.
    
    <?php
          namespace App;
          use Laravel\Passport\HasApiTokens;
          use Illuminate\Notifications\Notifiable;
          use Illuminate\Foundation\Auth\User as Authenticatable;
          class User extends Authenticatable
          {
                use HasApiTokens, Notifiable;
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
        }
      ?>
   
##NEXT

            app/Providers/AuthServiceProvider.php

            namespace App\Providers;
            use Laravel\Passport\Passport; 
            use Illuminate\Support\Facades\Gate; 
            use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
            class AuthServiceProvider extends ServiceProvider 
            { 
                /** 
                 * The policy mappings for the application. 
                 * 
                 * @var array 
                 */ 
                protected $policies = [ 
                    'App\Model' => 'App\Policies\ModelPolicy', 
                ];
            /** 
                 * Register any authentication / authorization services. 
                 * 
                 * @return void 
                 */ 
                public function boot() 
                { 
                    $this->registerPolicies(); 
                    Passport::routes(); 
                } 
            }


##config/auth.php

      return [
      'guards' => [ 
              'web' => [ 
                  'driver' => 'session', 
                  'provider' => 'users', 
              ], 
              'api' => [ 
                  'driver' => 'passport', 
                  'provider' => 'users', 
              ], 
          ],
    
    
##Step 5: Create API Route

    we will create API routes. Laravel provides api.php file for write web services route. So, let’s add a new route on that file.
    
    routes/api.php
    
    
    <?php
          /*
          |--------------------------------------------------------------------------
          | API Routes
          |--------------------------------------------------------------------------
          |
          | Here is where you can register API routes for your application. These
          | routes are loaded by the RouteServiceProvider within a group which
          | is assigned the "api" middleware group. Enjoy building your API!
          |
          */
          Route::post('login', 'API\UserController@login');
          Route::post('register', 'API\UserController@register');
          Route::group(['middleware' => 'auth:api'], function(){
          Route::post('details', 'API\UserController@details');
         });
         
         
   ##Step 6: Create the Controller
   
        last step we have to create a new controller and three API method, So first create a new directory “API” on Controllers folder. So let’s create UserController 
        
        <?php
          namespace App\Http\Controllers\API;
          use Illuminate\Http\Request; 
          use App\Http\Controllers\Controller; 
          use App\User; 
          use Illuminate\Support\Facades\Auth; 
          use Validator;
          class UserController extends Controller 
          {
          public $successStatus = 200;
          /** 
               * login api 
               * 
               * @return \Illuminate\Http\Response 
               */ 
              public function login(){ 
                  if(Auth::attempt(['email' => request('email'), 'password' => request('password')])){ 
                      $user = Auth::user(); 
                      $success['token'] =  $user->createToken('MyApp')-> accessToken; 
                      return response()->json(['success' => $success], $this-> successStatus); 
                  } 
                  else{ 
                      return response()->json(['error'=>'Unauthorised'], 401); 
                  } 
              }
          /** 
               * Register api 
               * 
               * @return \Illuminate\Http\Response 
               */ 
              public function register(Request $request) 
              { 
                  $validator = Validator::make($request->all(), [ 
                      'name' => 'required', 
                      'email' => 'required|email', 
                      'password' => 'required', 
                      'c_password' => 'required|same:password', 
                  ]);
          if ($validator->fails()) { 
                      return response()->json(['error'=>$validator->errors()], 401);            
                  }
          $input = $request->all(); 
                  $input['password'] = bcrypt($input['password']); 
                  $user = User::create($input); 
                  $success['token'] =  $user->createToken('MyApp')-> accessToken; 
                  $success['name'] =  $user->name;
          return response()->json(['success'=>$success], $this-> successStatus); 
              }
          /** 
               * details api 
               * 
               * @return \Illuminate\Http\Response 
               */ 
              public function details() 
              { 
                  $user = Auth::user(); 
                  return response()->json(['success' => $user], $this-> successStatus); 
              } 
          }
          
          
 ##run our example so run below command to quick run:
 
    php artisan serve
    
    
 #TEST THE API
 
 localhost:8080/api/login
 localhost:8080/api/register
 localhost:8080/api/details
 
 
 





