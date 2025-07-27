use Object::Pad ':experimental(:all)';

package App::OpenSSL::CA::Base;
role App::OpenSSL::CA::Base;

use utf8;
use v5.40;

use Time::HiRes ();

method epoch : common ($join = '') {
    join $join, Time::HiRes::gettimeofday;
}
