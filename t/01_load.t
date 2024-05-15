use v5.26;
use warnings;

use Test2::V0;

use ok 'Authorization::AccessControl';

use ok 'Authorization::AccessControl', qw(ac);

use ok 'Authorization::AccessControl::Privilege';

use ok 'Authorization::AccessControl::YieldResult';

use ok 'Authorization::AccessControl::Predicate';

done_testing;
