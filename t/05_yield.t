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

my $r = [];
ac->request->with_action('read')->with_resource('Post')->yield(sub() { 'post' })
  ->denied(sub { push($r->@*, "d") });
is($r, ['d'], 'yield without necessary attributes');

$r = [];
ac->request->with_action('read')->with_resource('Post')->with_attributes({own => true})
  ->yield(sub() { 'post' })
  ->granted(sub($entity) { push($r->@*, $entity) });
is($r, ['post'], 'yield with necessary attributes');

$r = [];
ac->request->with_action('read')->with_resource('Post')
  ->with_dynamic_attribute_extraction_function(sub($obj) { return { own => true } })
  ->yield(sub() { 'post' })
  ->granted(sub($entity) { push($r->@*, $entity) });
is($r, ['post'], 'yield with dynamic attributes');

$r = [];
ac->request->with_action('read')->with_resource('Post')
  ->with_dynamic_attribute_extraction_function(sub($obj) { return { own => false } })
  ->yield(sub() { 'post' })
  ->denied(sub() { push($r->@*, 'd') });
is($r, ['d'], 'yield with incorrect dynamic attributes');

done_testing;
