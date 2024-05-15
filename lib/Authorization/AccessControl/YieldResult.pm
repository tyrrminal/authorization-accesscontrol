package Authorization::AccessControl::YieldResult;
use v5.26;
use warnings;

use Readonly;

use experimental qw(signatures);

sub new($class, %params) {
  my $granted = delete($params{granted});
  $granted = !!$granted if(defined($granted)); #force into boolean/undef
  my $entity = delete($params{entity});
  undef($entity) unless($granted); # ensure we don't hold the protected value if access is not granted
  
  die("Unsupported params: ", join(', ', keys(%params))) if(keys(%params));

  Readonly::Scalar my $data => {
    _granted => $granted,
    _entity  => $entity,
  };

  bless($data, $class);
}

sub granted($self, $sub) {
  $sub->($self->{_entity}) if($self->{_granted});
  return $self;
}

sub denied($self, $sub) {
  $sub->() if(defined($self->{_granted}) && !$self->{_granted});
  return $self
}

sub null($self, $sub) {
  $sub->() if(!defined($self->{_granted}));
  return $self
}

sub is_granted($self) {
  return ($self->{_granted}//0) != 0;
}

1;
