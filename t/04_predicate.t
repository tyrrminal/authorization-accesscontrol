use v5.26;
use warnings;

use Test2::V0;

use Authorization::AccessControl qw(ac);

use experimental qw(signatures);

use constant true => !0;
use constant false => !1;

ac
  ->role('admin')
    ->grant(User => 'read')
    ->grant(User => 'update')
    ->grant(User => 'delete')
    ->grant(Post => 'delete')
  ->role('super')
    ->grant(User => 'ban')
  ->role
    ->grant(Post => 'create')
    ->grant(Post => 'read',   {own => true})
    ->grant(Post => 'delete', {own => true});

is(
  !!ac->roles(qw(admin super))->perform('read')->on_resource('User')->permitted,
  true, 'Admin/Super read user permitted');

is(
  !!ac->roles()->perform('read')->on_resource('Post')->with_attributes({own => true})->permitted,
  true, 'User read own post permitted');

is(
  !!ac->roles()->perform('read')->on_resource('Post')->permitted,
  false, 'Not permitted without attributes');

done_testing;
