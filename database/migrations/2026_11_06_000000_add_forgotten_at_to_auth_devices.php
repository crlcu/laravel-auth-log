<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Known accounts are looked up by the device cookie alone, before anyone
     * signs in, so the token hash gets an index of its own.
     */
    public function up(): void
    {
        Schema::table('auth_devices', function (Blueprint $table) {
            $table->timestamp('forgotten_at')->nullable()->after('signed_out_at');

            $table->index('device_token_hash');
        });
    }

    public function down(): void
    {
        Schema::table('auth_devices', function (Blueprint $table) {
            $table->dropIndex(['device_token_hash']);
            $table->dropColumn('forgotten_at');
        });
    }
};
