INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (1, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (2, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (3, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (4, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (5, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (6, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (7, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (8, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (9, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (10, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (11, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (12, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (13, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (14, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (15, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (16, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (17, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (18, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (19, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (20, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (21, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (22, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (23, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (24, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (25, 'Andres', 'Guzman', 'profesor@bolsadeideas.com', '2017-08-28', '');
INSERT INTO clientes (id, nombre, apellido, email, create_at, foto) VALUES (26, 'John', 'Doe', 'john.doe@gmail.com', '2017-08-28', '');

INSERT INTO productos (nombre, precio, create_at) VALUES ('Panasonic Pantalla LCD', 259990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Sony Camara digital DSC-W320B', 123490, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Apple iPod shuffle', 1499990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Sony Notebook Z110', 37990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Hewlett Packard Multifuncional F2280', 69990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Bianchi Bicicleta Aro 26', 69990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Mica Comoda 5 Cajones', 299990, NOW());

INSERT INTO facturas (descripcion, observacion, cliente_id, create_at) VALUES ('Factura equipos de oficina', null, 1, NOW());
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES (1,1,1);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES (2,1,4);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES (1,1,5);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES (1,1,7);

INSERT INTO facturas (descripcion, observacion, cliente_id, create_at) VALUES ('Factura Bicicleta', 'Alguna nota importante!', 1, NOW());
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES (3,2,6);

INSERT INTO users (username, password, enable) VALUES ('andres', '$2a$10$ayinZFrCg.GvjU.CPxvUBehgi/y5YUMoxkhhGSP9QRhL77XO8Fa1C', 1);
INSERT INTO users(username, password, enable) VALUES ('admin', '$2a$10$XezTQP9nIPsLfND8dhfE3OUZkQZz3A9lU0AmeiCxo2GW.73AMqUPm', 1);


INSERT INTO authorities (user_id, authority) VALUES (1, 'ROLE_USER');
INSERT INTO authorities (user_id, authority) VALUES (2, 'ROLE_ADMIN');
INSERT INTO authorities (user_id, authority) VALUES (2, 'ROLE_USER');