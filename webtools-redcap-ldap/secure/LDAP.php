<?php

class LDAP
{
  private $ldap_servers = array();  // List of servers to round-robin through when attempting to connect
  private $ldap_handle = null;      // LDAP server handle
  private $ldap = false;            // Flag indicating whether we loaded properly
  private $ldap_dn;
  private $connected_server;
  private $n_rs = 1;
  private $rs = array();
  private $rs_row = array();

  public function __construct()
  {
    $this->setServers( array(
        'ldap.stanford.edu',
        'ldap.stanford.edu',
        'ldap.stanford.edu'
      )
    );

    $this->connect();

    $this->setDN( "cn=people,dc=stanford,dc=edu" );
  }

  public function __destruct()
  {
    if ( $this->ldap )
      $this->close();
  }

  public function connect()
  {
    $this->ldap = false;
    $this->connected_server = null;
    foreach( $this->ldap_servers as $server )
    {
      $this->ldap_handle = ldap_connect( $server );
      if ( $this->ldap_handle )
      {
        if ( ldap_bind( $this->ldap_handle ) )
        {
          ldap_set_option( $this->ldap_handle, LDAP_OPT_PROTOCOL_VERSION, 3 );

          //if ( !getenv( 'KRB5CCNAME' ) )
            putenv('KRB5CCNAME=FILE:/etc/krb5cc_ldap.new');
            #putenv('KRB5CCNAME=FILE:/etc/httpd/conf/webauth/krb5cc_ldap');
            //putenv('KRB5CCNAME=FILE:/tmp/service-apache.tkt');
          if( $this->ldap = @ldap_bind( $this->ldap_handle, "", ""  ) )
          {
            $this->connected_server = $server;
            break;
          }
        }
      }
    }
    return $this->ldap;
  }

  public function getConnectedServer()
  {
    return $this->connected_server;
  }

  public function setDN( $dn )
  {
    $this->ldap_dn = $dn;
  }

  public function getDN()
  {
    return $this->ldap_dn;
  }

  public function close()
  {
    if ( $this->ldap )
    {
      ldap_close( $this->ldap_handle );
      $this->ldap_handle = null;
      $this->ldap = false;
      $this->connected_server = null;
      $this->n_rs = 0;
      $this->rs = array();
      $this->rs_row = array();
    }
  }

  public function isAlive()
  {
    return $this->ldap;
  }

  // RESULT FUNCTIONS

  public function getRow( $id = 0 )
  {
    // Not a valid id
    if ( !isset( $this->rs[ $id ] ) || $id >= $this->n_rs )
      return null;

    // Exceeded the results
    if ( $this->rs_row[ $id ] >= $this->rs[ $id ]['count'] )
      return null;

    // Fetch an assoc array for this row (indexed with both hash key and array numeric index)
    $res = array();
    for( $i=0; $i<$this->rs[ $id ][ $this->rs_row[ $id ] ]['count']; $i++ )
    {
      $item = & $this->rs[ $id ][ $this->rs_row[ $id ] ][ $this->rs[ $id ][ $this->rs_row[ $id ] ][ $i ] ];
      if ( $item['count'] == 1 )
      {
        $res[ $this->rs[ $id ][ $this->rs_row[ $id ] ][ $i ] ] = $item[0];
        $res[ $i ] = $item[0];
      } else
      {
        // This item is a list so copy array to return $res
        $res[ $this->rs[ $id ][ $this->rs_row[ $id ] ][ $i ] ] = array();
        $res[ $i ] = array();
        for( $j=0; $j<$item['count']; $j++ )
        {
          $res[ $this->rs[ $id ][ $this->rs_row[ $id ] ][ $i ] ][] = $item[ $j ];
          $res[ $i ][] = $item[ $j ];
        }
      }
    }
    $this->rs_row[ $id ]++;
    return $res;
  }

  public function getNumRows( $id = 0 )
  {
    if ( !isset( $this->rs[ $id ] ) || $id >= $this->n_rs )
      return 0;

    return $this->rs[ $id ]['count'];
  }

  public function getRowNumItems( $id = 0 )
  {
    if ( !isset( $this->rs[ $id ] ) || $id >= $this->n_rs )
      return 0;

    return $this->rs[ $id ][ $this->rs_row[ $id ] ]['count'];
  }

  // QUERY FUNCTIONS

  public function query( $filter, $only = array() )
  {
    if ( is_array( $filter ) )
    {
      if ( count( $filter ) > 1 )
      {
        $filter = '(&(' . implode( ')(', $filter ) . '))';
      } else if ( count( $filter ) == 1 )
      {
        foreach( $filter as $x )
          $filter = '(' . $x . ')';
      } else
      {
        $filter = "";
      }
    }

    if ( count( $only ) > 0 )
      $result = ldap_search( $this->ldap_handle, $this->ldap_dn, $filter, $only );
    else
      $result = ldap_search( $this->ldap_handle, $this->ldap_dn, $filter );

    // Koorosh - be sure to remove!
    //file_put_contents( '/var/www/html/core/logs/' . date( 'Y-m-d' ) . '-ldap.log', date( 'Y-m-d H:i:s' ) . "\t" . $this->ldap_dn . "\t" . $filter . "\n", FILE_APPEND );

    if ( $result )
    {
      $this->rs[ $this->n_rs ] = ldap_get_entries( $this->ldap_handle, $result );
      $this->rs_row[ $this->n_rs ] = 0;
      return $this->n_rs++;
    }
    return null;
  }

  public function query_suid( $suid )
  {
    return $this->query( 'uid=' . $suid );
  }

  public function query_group( $group )
  {
    return $this->query( 'suPrivilegeGroup=' . $group );
  }

  // LDAP SERVER CONFIG

  public function getServers()
  {
    return $this->ldap_servers;
  }

  public function setServers( $servers )
  {
    $this->ldap_servers = $servers;
  }

  public function addServer( $server )
  {
    if ( !in_array( $server, $this->ldap_servers ) )
      $this->ldap_servers[] = $server;
  }

  public function removeServer( $drop_server )
  {
    foreach( $this->ldap_servers as $index => $server )
    {
      if ( $drop_server == $server )
      {
        unset( $this->ldap_servers[ $index ] );
        break;
      }
    }
  }
}