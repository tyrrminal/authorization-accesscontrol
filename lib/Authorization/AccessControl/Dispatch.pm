package Authorization::AccessControl::Dispatch;
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

=head1 AUTHOR

Mark Tyrrell C<< <mark@tyrrminal.dev> >>

=head1 LICENSE

Copyright (c) 2024 Mark Tyrrell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

=cut

1;

__END__
