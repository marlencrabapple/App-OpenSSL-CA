use Object::Pad ':experimental(:all)';

package App::OpenSSL::SAN;

class App::OpenSSL::SAN;

use utf8;
use v5.40;

use Object::Pad ':experimental(:all)';

method $SAN_tostr : common ($SAN, %opts) {
    my $SAN_str = "subjectAltName=";

    foreach my $key ( keys %$SAN ) {
        my $i = 0;
        foreach my $entry ( $SAN->$key->@* ) {
            $SAN_str .= uc($key) . ".0:$entry";
            $i++;
        }
    }
}

use overload "" => $SAN_tostr;

field $ip    : param = [q'127.0.0.1 ::1'];
field $dns   : param = [qw(localhost)];
field $email : param = undef;

ADJUSTPARAMS($params) {
    $self->doctor_SAN(%$params)
};

method add_ip ($ip) {
    $self->add_to_san( ip => $ip );
}

method doctor_SAN { $self->append_to_SAN(@_) }

method add_to_san (%fields) {
    foreach my ( $field, $val ) (%fields) {
        $self->$field isa 'ARRAY'
          ? push $self->$field->@*, $val
          : $self->add_to_san( $field => $val );
    }
}

method SAN : common (%fields) {
    SAN->new( %fields{q'ip dns email'} );
}

method as_ASN1(%opts) {
}

method tostr ( $SAN, %opts ) {

}

