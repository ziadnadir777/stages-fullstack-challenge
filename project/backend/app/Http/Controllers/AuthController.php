<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash; // Pour hasher à l'inscription
use Illuminate\Support\Facades\Auth; // Pour vérifier à la connexion

class AuthController extends Controller
{
    /**
     * Handle user login.
     */
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        // CORRECTION SEC-001 : Utilisation de Auth::attempt
        // Cette méthode vérifie le hash de manière sécurisée.
        // Plus de comparaison en clair ($user->password === $pwd) !
        if (Auth::attempt($credentials)) {
            $user = Auth::user();

            // (Optionnel) Création de token si tu utilises Sanctum, 
            // sinon on renvoie juste les infos comme avant.
            
            return response()->json([
                'message' => 'Login successful',
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                ],
            ]);
        }

        return response()->json(['message' => 'Invalid credentials'], 401);
    }

    /**
     * Handle user registration.
     */
    public function register(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            // CORRECTION SEC-001 : Hashage immédiat du mot de passe
            'password' => Hash::make($validated['password']),
        ]);

        return response()->json([
            'message' => 'User registered successfully',
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
            ],
        ], 201);
    }

    /**
     * Get current user info.
     */
    public function me(Request $request)
    {
        // Note : Cette méthode n'est pas très sécurisée (IDOR), 
        // mais on se concentre sur le mot de passe pour ce ticket.
        $userId = $request->input('user_id');
        
        if (!$userId) {
            return response()->json(['message' => 'Not authenticated'], 401);
        }

        $user = User::find($userId);

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        return response()->json([
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
        ]);
    }
}