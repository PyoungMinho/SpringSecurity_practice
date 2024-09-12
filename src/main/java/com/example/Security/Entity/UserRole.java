package com.example.Security.Entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@Table(name = "members_roles")
@AllArgsConstructor
@NoArgsConstructor
public class UserRole {
    @Id
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "role")
    private String role;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "user_id", updatable = false, insertable = false)
    private User user;
}
