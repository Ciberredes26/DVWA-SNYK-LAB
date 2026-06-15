<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            //MITIGACION APLICADA: prepared statement con bind_param
            //ANTES (Vulnerabilidad)
            // Check database
            //$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            //$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

            //DESPUES (Seguro)
            $stmt = $GLOBALS["___mysqli_ston"]->prepare(
                "SELECT first_name, last_name FROM users WHERE user_id = ?"
            );

            // bind_param: 's' = string, luego la variable $id
            $stmt->bind_param('s', $id);
            $stmt->execute();
            $generesult = $stmt->get_result();

            if( $generesult->num_rows <= 0 ) {
                // No results found
                $html .= '<pre>User ID is MISSING from the database.</pre>';
            } else {
                // Get results
                while( $row = $generesult->fetch_assoc() ) {
                    // Get values
                    $first = $row["first_name"];
                    $last  = $row["last_name"];

                    // ANTES (Prevenir XSS)
                    // Feedback for end user
                    //$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                }

                    //DESPUES (MITIGACION)
                    $html .= "<pre>ID: " . htmlspecialchars($id, ENT_QUOTES, 'UTF-8')
                           . "<br />First name: " . htmlspecialchars($first, ENT_QUOTES, 'UTF-8')
                           . "<br />Surname: "    . htmlspecialchars($last, ENT_QUOTES, 'UTF-8')
                           . "</pre>";
                }
            }

            $generesult->free();
            $stmt->close();
            mysqli_close($GLOBALS["___mysqli_ston"]);
            break;

        case SQLITE:
            global $sqlite_db_connection;

            //#$sqlite_db_connection = new SQLite3($_DVWA['SQLITE_DB']);
            //#$sqlite_db_connection->enableExceptions(true);
            // MITIGACIÓN APLICADA: Prepared statement para SQLite
            // ANTES (vulnerable):
            //$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            // #print $query;
            //try {
            //$results = $sqlite_db_connection->query($query);
            //} catch (Exception $e) {
            //echo 'Caught exception: ' . $e->getMessage();
            //exit();
            //}

            // MITIGACION DESPUÉS (seguro):
            $stmt = $sqlite_db_connection->prepare(
                "SELECT first_name, last_name FROM users WHERE user_id = ?"
            );
            $stmt->bindValue(1, $id, SQLITE3_TEXT);

            try {
                $results = $stmt->execute();

			                if( $results ) {
                    while( $row = $results->fetchArray(SQLITE3_ASSOC) ) {
                        $first = $row["first_name"];
                        $last  = $row["last_name"];

                        // MITIGACION Escapar output
                        $html .= "<pre>ID: " . htmlspecialchars($id, ENT_QUOTES, 'UTF-8')
                               . "<br />First name: " . htmlspecialchars($first, ENT_QUOTES, 'UTF-8')
                               . "<br />Surname: "    . htmlspecialchars($last, ENT_QUOTES, 'UTF-8')
                               . "</pre>";
                    }
                } else {
                    $html .= '<pre>User ID is MISSING from the database.</pre>';
                }

            } catch (Exception $e) {
                echo 'Caught exception: ' . $e->getMessage();
                exit();
            }
            break;
    }
}

?>
