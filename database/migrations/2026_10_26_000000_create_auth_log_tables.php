<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_devices', function (Blueprint $table) {
            $table->id();
            $table->morphs('authenticatable');
            $table->string('device_token_hash', 64);
            $table->string('remember_token_hash', 64)->nullable();
            $table->string('session_id')->nullable();
            $table->string('browser')->nullable();
            $table->string('platform')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->char('country', 2)->nullable();
            $table->string('city')->nullable();
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at')->index();
            $table->timestamp('verified_at')->nullable();
            $table->string('verification_code_hash', 64)->nullable();
            $table->timestamp('verification_sent_at')->nullable();
            $table->unsignedTinyInteger('verification_attempts')->default(0);
            $table->timestamp('signed_out_at')->nullable();
            $table->timestamps();

            $table->unique(['authenticatable_type', 'authenticatable_id', 'device_token_hash'], 'auth_devices_token_unique');
        });

        Schema::create('auth_events', function (Blueprint $table) {
            $table->id();
            $table->nullableMorphs('authenticatable');
            $table->foreignId('device_id')->nullable()->constrained('auth_devices')->nullOnDelete();
            $table->string('type');
            $table->string('email')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->char('country', 2)->nullable();
            $table->string('city')->nullable();
            $table->boolean('is_suspicious')->default(false);
            $table->json('suspicion_reasons')->nullable();
            $table->timestamp('created_at')->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_events');
        Schema::dropIfExists('auth_devices');
    }
};
